// SPDX-License-Identifier: MIT OR Apache-2.0

//! A GPU backend for the sweeps large enough to deserve one.
//!
//! The exhaustive periodic sweeps are the perfect shape for a device:
//! hundreds of millions of independent keys, a few dozen integer operations each, and a table small enough to sit in device memory and stay there.
//! A key length of seven over three families is twenty-four billion keys, which is a long wait on the processor and minutes here.
//!
//! The kernel never materialises a plaintext.
//! A trigram index can be carried forward one letter at a time, so each thread holds an accumulator per language and the running index, and nothing that scales with the length of the message.
//!
//! The key space is split so the device only ever counts within a `u32`.
//! Longer keys are covered by fixing a prefix on the host and dispatching once per prefix, which also keeps a single dispatch short enough not to trip a driver watchdog.

use crate::alphabet::{ALPHABET, Letter};
use crate::ciphers::enigma;
use crate::ciphers::periodic::{self, Family};

/// The compute shader, in WGSL so the same source runs on Metal, Vulkan and DirectX.
const SHADER: &str = include_str!("gpu/periodic.wgsl");

/// The Enigma rotor sweep.
const ENIGMA_SHADER: &str = include_str!("gpu/enigma.wgsl");

/// Where each block of the packed Enigma table starts, in words.
const T_FORWARD: usize = 0;
const T_BACKWARD: usize = 208;
const T_NOTCH: usize = 416;
const T_REFLECTOR: usize = 424;
const T_ORDERS: usize = 424 + 104 * 26;

/// Threads per dispatch.
/// Each strides through the key range.
const THREADS: u32 = 256 * 512;

/// Threads per workgroup, matching the shader.
const WORKGROUP: u32 = 256;

/// The most key digits a single dispatch enumerates, so the count fits a `u32`.
const MAX_LOW_DIGITS: usize = 6;

/// A device, ready to sweep.
pub struct Gpu {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::ComputePipeline,
    layout: wgpu::BindGroupLayout,
    enigma_pipeline: wgpu::ComputePipeline,
    enigma_layout: wgpu::BindGroupLayout,
    /// What the adapter calls itself, for the report.
    pub name: String,
}

fn words_to_bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_ne_bytes()).collect()
}

fn floats_to_bytes(values: &[f32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_ne_bytes()).collect()
}

/// Pad every gram's row of log probabilities out to a multiple of four.
///
/// The shader reads the table as aligned vectors; the padding is filled with a value that can never win a maximum.
fn widen(table: &[f32], langs: usize, padded: usize) -> Vec<f32> {
    let grams = table.len() / langs.max(1);
    let mut wide = vec![-1.0e30f32; grams * padded];
    for g in 0..grams {
        wide[g * padded..g * padded + langs].copy_from_slice(&table[g * langs..g * langs + langs]);
    }
    wide
}

/// The digits of a key prefix, most significant first.
fn spell_prefix(mut index: u64, len: usize) -> [u32; 16] {
    let mut prefix = [0u32; 16];
    for slot in prefix[..len].iter_mut().rev() {
        *slot = (index % ALPHABET as u64) as u32;
        index /= ALPHABET as u64;
    }
    prefix
}

/// The key a dispatch's winning index stands for.
fn rebuild_key(index: u32, period: usize, prefix_len: usize, prefix: &[u32; 16]) -> Vec<Letter> {
    let mut key = vec![0u8; period];
    let mut rest = u64::from(index);
    for slot in key[prefix_len..].iter_mut().rev() {
        *slot = (rest % ALPHABET as u64) as u8;
        rest /= ALPHABET as u64;
    }
    for (slot, &digit) in key[..prefix_len].iter_mut().zip(prefix) {
        *slot = digit as u8;
    }
    key
}

/// The parameter block the shader reads.
#[allow(clippy::too_many_arguments)]
fn params_for(
    n: usize,
    period: usize,
    padded: usize,
    order: usize,
    family: usize,
    count: u64,
    prefix_len: usize,
    prefix: &[u32; 16],
) -> Vec<u32> {
    let mut params = vec![
        n as u32,
        period as u32,
        padded as u32,
        order as u32,
        (ALPHABET as u32).pow(order as u32 - 1),
        family as u32,
        count as u32,
        THREADS,
        prefix_len as u32,
        (padded / 4) as u32,
        0,
        0,
    ];
    params.extend_from_slice(prefix);
    params
}

fn bytes_to_words(bytes: &[u8]) -> Vec<u32> {
    bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|&c| u32::from_ne_bytes(c))
        .collect()
}

impl Gpu {
    /// Open a device, or explain why not.
    ///
    /// # Errors
    ///
    /// Fails when no adapter supports compute, which is the normal case in a container or over a remote session.
    pub fn open() -> Result<Gpu, String> {
        let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor::default());
        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            ..Default::default()
        }))
        .map_err(|e| format!("no GPU adapter: {e}"))?;
        let name = adapter.get_info().name;
        // Ask for what the adapter actually has.
        // The portable defaults cap storage buffers at four and buffer sizes well below the table plus the output, and this tool would rather use the machine it is on.
        let limits = adapter.limits();
        let (device, queue) = pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor {
            label: Some("cipher-break"),
            required_features: wgpu::Features::empty(),
            required_limits: limits,
            ..Default::default()
        }))
        .map_err(|e| format!("no GPU device: {e}"))?;

        let module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("periodic"),
            source: wgpu::ShaderSource::Wgsl(SHADER.into()),
        });
        let entries: Vec<wgpu::BindGroupLayoutEntry> = (0..4u32)
            .map(|i| wgpu::BindGroupLayoutEntry {
                binding: i,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: i < 3 },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            })
            .collect();
        let layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("periodic"),
            entries: &entries,
        });
        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("periodic"),
            bind_group_layouts: &[&layout],
            push_constant_ranges: &[],
        });
        let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("periodic"),
            layout: Some(&pipeline_layout),
            module: &module,
            entry_point: Some("sweep"),
            compilation_options: wgpu::PipelineCompilationOptions::default(),
            cache: None,
        });
        let enigma_module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("enigma"),
            source: wgpu::ShaderSource::Wgsl(ENIGMA_SHADER.into()),
        });
        let enigma_entries: Vec<wgpu::BindGroupLayoutEntry> = (0..5u32)
            .map(|i| wgpu::BindGroupLayoutEntry {
                binding: i,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: i < 4 },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            })
            .collect();
        let enigma_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("enigma"),
            entries: &enigma_entries,
        });
        let enigma_pipeline_layout =
            device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
                label: Some("enigma"),
                bind_group_layouts: &[&enigma_layout],
                push_constant_ranges: &[],
            });
        let enigma_pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
            label: Some("enigma"),
            layout: Some(&enigma_pipeline_layout),
            module: &enigma_module,
            entry_point: Some("sweep"),
            compilation_options: wgpu::PipelineCompilationOptions::default(),
            cache: None,
        });

        Ok(Gpu {
            device,
            queue,
            pipeline,
            layout,
            enigma_pipeline,
            enigma_layout,
            name,
        })
    }

    /// Sweep the rotor half of an Enigma key on the device.
    ///
    /// Steered by one language rather than a bank of them.
    /// The sweep's job is to find the rotors, the plugboard is grown afterwards on the processor, and a single accumulator is what keeps a thread's working set small enough to stay in registers.
    ///
    /// Returns `(score, index)` pairs, where the index decomposes as `order * reflectors * 17576 + reflector * 17576 + position`.
    #[must_use]
    pub fn sweep_enigma(
        &self,
        ct: &[Letter],
        logp: &[f32],
        order: usize,
        orders: &[[usize; 3]],
        reflectors: &[[u8; ALPHABET]],
        keep: usize,
    ) -> Vec<(f64, u64)> {
        let (forward, backward, notches) = enigma::rotor_tables();
        let mut tables = vec![0u32; T_ORDERS + orders.len() * 3];
        for (i, &v) in forward.iter().enumerate() {
            tables[T_FORWARD + i] = u32::from(v);
        }
        for (i, &v) in backward.iter().enumerate() {
            tables[T_BACKWARD + i] = u32::from(v);
        }
        for (i, &v) in notches.iter().enumerate() {
            tables[T_NOTCH + i] = v;
        }
        for (r, reflector) in reflectors.iter().enumerate() {
            for (i, &v) in reflector.iter().enumerate() {
                tables[T_REFLECTOR + r * ALPHABET + i] = u32::from(v);
            }
        }
        for (o, rotors) in orders.iter().enumerate() {
            for (i, &v) in rotors.iter().enumerate() {
                tables[T_ORDERS + o * 3 + i] = v as u32;
            }
        }

        let positions = (ALPHABET as u64).pow(3);
        let count = orders.len() as u64 * reflectors.len() as u64 * positions;
        let chunk = count.div_ceil(u64::from(THREADS));
        let params = vec![
            ct.len() as u32,
            count as u32,
            THREADS,
            orders.len() as u32,
            reflectors.len() as u32,
            positions as u32,
            (ALPHABET as u32).pow(order as u32 - 1),
            order as u32,
            chunk as u32,
            0,
            0,
            0,
        ];

        let ct_buffer = self.storage(
            "ct",
            &words_to_bytes(&ct.iter().map(|&l| u32::from(l)).collect::<Vec<_>>()),
        );
        let tables_buffer = self.storage("tables", &words_to_bytes(&tables));
        let logp_buffer = self.storage("logp", &floats_to_bytes(logp));
        let params_buffer = self.storage("params", &words_to_bytes(&params));
        let out_len = THREADS as usize * 2;
        let out_buffer = self.readable("out", (out_len * 4) as u64);
        let out_staging = self.staging("out-read", (out_len * 4) as u64);

        let bind = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("enigma"),
            layout: &self.enigma_layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: ct_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: tables_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: logp_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 3,
                    resource: params_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 4,
                    resource: out_buffer.as_entire_binding(),
                },
            ],
        });
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor::default());
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor::default());
            pass.set_pipeline(&self.enigma_pipeline);
            pass.set_bind_group(0, &bind, &[]);
            pass.dispatch_workgroups(THREADS / WORKGROUP, 1, 1);
        }
        encoder.copy_buffer_to_buffer(&out_buffer, 0, &out_staging, 0, (out_len * 4) as u64);
        self.queue.submit(Some(encoder.finish()));

        let packed = bytes_to_words(&self.read(&out_staging));
        let mut found: Vec<(f64, u64)> = packed
            .as_chunks::<2>()
            .0
            .iter()
            .filter(|c| f32::from_bits(c[0]).is_finite() && f32::from_bits(c[0]) > -1.0e29)
            .map(|c| (f64::from(f32::from_bits(c[0])), u64::from(c[1])))
            .collect();
        found.sort_unstable_by(|a, b| b.0.total_cmp(&a.0));
        found.dedup_by(|a, b| a.1 == b.1);
        found.truncate(keep.max(1));
        found
    }

    /// Exhaust every key of a given period across the Vigenere family.
    ///
    /// Returns the best raw fits found, with the key that produced each.
    /// The scores are the same quantity the processor computes — the shader reads the same interleaved table — so the two backends can be checked against each other, and are.
    #[must_use]
    pub fn sweep_periodic(
        &self,
        ct: &[Letter],
        table: &[f32],
        langs: usize,
        order: usize,
        period: usize,
        keep: usize,
    ) -> Vec<(f64, Family, Vec<Letter>)> {
        let low = period.min(MAX_LOW_DIGITS);
        let prefix_len = period - low;
        let count = (ALPHABET as u64).pow(low as u32);
        let prefixes = (ALPHABET as u64).pow(prefix_len as u32);
        let padded = langs.div_ceil(4) * 4;

        let ct_buffer = self.storage(
            "ct",
            &words_to_bytes(&ct.iter().map(|&l| u32::from(l)).collect::<Vec<_>>()),
        );
        let table_buffer = self.storage("table", &floats_to_bytes(&widen(table, langs, padded)));
        let out_len = THREADS as usize * 2;
        let out_buffer = self.readable("out", (out_len * 4) as u64);
        let out_staging = self.staging("out-read", (out_len * 4) as u64);

        let mut found: Vec<(f64, Family, Vec<Letter>)> = Vec::new();
        for (family_index, family) in periodic::FAMILIES.into_iter().enumerate() {
            for prefix_index in 0..prefixes {
                let prefix = spell_prefix(prefix_index, prefix_len);
                let params = params_for(
                    ct.len(),
                    period,
                    padded,
                    order,
                    family_index,
                    count,
                    prefix_len,
                    &prefix,
                );
                let params_buffer = self.storage("params", &words_to_bytes(&params));
                self.dispatch(
                    &ct_buffer,
                    &table_buffer,
                    &params_buffer,
                    &out_buffer,
                    &out_staging,
                    out_len,
                );
                let packed = bytes_to_words(&self.read(&out_staging));
                for &c in packed.as_chunks::<2>().0 {
                    let (score, index) = (f32::from_bits(c[0]), c[1]);
                    if !score.is_finite() || score < -1.0e29 {
                        continue;
                    }
                    found.push((
                        f64::from(score),
                        family,
                        rebuild_key(index, period, prefix_len, &prefix),
                    ));
                }
                found.sort_unstable_by(|a, b| b.0.total_cmp(&a.0));
                found.dedup_by(|a, b| a.1 == b.1 && a.2 == b.2);
                found.truncate(keep.max(1) * 4);
            }
        }
        found.truncate(keep.max(1));
        found
    }

    /// Submit one dispatch and copy its answers back.
    fn dispatch(
        &self,
        ct: &wgpu::Buffer,
        table: &wgpu::Buffer,
        params: &wgpu::Buffer,
        out: &wgpu::Buffer,
        staging: &wgpu::Buffer,
        out_len: usize,
    ) {
        let bind = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("periodic"),
            layout: &self.layout,
            entries: &[
                wgpu::BindGroupEntry {
                    binding: 0,
                    resource: ct.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 1,
                    resource: table.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 2,
                    resource: params.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding: 3,
                    resource: out.as_entire_binding(),
                },
            ],
        });
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor::default());
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor::default());
            pass.set_pipeline(&self.pipeline);
            pass.set_bind_group(0, &bind, &[]);
            pass.dispatch_workgroups(THREADS / WORKGROUP, 1, 1);
        }
        encoder.copy_buffer_to_buffer(out, 0, staging, 0, (out_len * 4) as u64);
        self.queue.submit(Some(encoder.finish()));
    }

    fn storage(&self, label: &str, bytes: &[u8]) -> wgpu::Buffer {
        use wgpu::util::DeviceExt as _;
        self.device
            .create_buffer_init(&wgpu::util::BufferInitDescriptor {
                label: Some(label),
                contents: bytes,
                usage: wgpu::BufferUsages::STORAGE,
            })
    }

    fn readable(&self, label: &str, size: u64) -> wgpu::Buffer {
        self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some(label),
            size,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
            mapped_at_creation: false,
        })
    }

    fn staging(&self, label: &str, size: u64) -> wgpu::Buffer {
        self.device.create_buffer(&wgpu::BufferDescriptor {
            label: Some(label),
            size,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        })
    }

    fn read(&self, buffer: &wgpu::Buffer) -> Vec<u8> {
        let slice = buffer.slice(..);
        let (tx, rx) = std::sync::mpsc::channel();
        slice.map_async(wgpu::MapMode::Read, move |r| {
            let _ = tx.send(r);
        });
        let _ = self.device.poll(wgpu::PollType::Wait {
            submission_index: None,
            timeout: None,
        });
        let _ = rx.recv();
        let data = slice.get_mapped_range().to_vec();
        let _ = slice;
        buffer.unmap();
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opening_a_device_either_works_or_says_why() {
        match Gpu::open() {
            Ok(gpu) => assert!(!gpu.name.is_empty()),
            Err(message) => assert!(!message.is_empty()),
        }
    }
}
