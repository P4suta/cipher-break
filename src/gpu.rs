// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::alphabet::{ALPHABET, Letter};
use crate::ciphers::enigma;
use crate::ciphers::periodic::{self, Family};
use crate::enigma_types::{Indicator, Ring};

const SHADER: &str = include_str!("gpu/periodic.wgsl");

const ENIGMA_SHADER: &str = include_str!("gpu/enigma.wgsl");

const PLUGBOARD_SHADER: &str = include_str!("gpu/plugboard.wgsl");

const BOMBE_SHADER: &str = include_str!("gpu/bombe.wgsl");

const BOMBE_WORKGROUP: u32 = 128;

pub const BOMBE_MAX_CRIB: usize = 32;

const T_FORWARD: usize = 0;
const T_BACKWARD: usize = T_FORWARD + enigma::ROTOR_COUNT * ALPHABET;
const T_NOTCH: usize = T_BACKWARD + enigma::ROTOR_COUNT * ALPHABET;
const T_REFLECTOR: usize = T_NOTCH + enigma::ROTOR_COUNT;

const THREADS: u32 = 256 * 512;

const WORKGROUP: u32 = 256;

const MAX_LOW_DIGITS: usize = 6;

pub struct EnigmaJob<'a> {
    pub ct: &'a [Letter],
    pub logp: &'a [f32],
    pub order: usize,
    pub orders: &'a [[usize; 3]],
    pub reflectors: &'a [[u8; ALPHABET]],
    pub rings: usize,
    pub middles: usize,
    pub keep: usize,
}

fn decode_stops(
    hits: &[u32],
    order: usize,
    rings: u32,
    middles: u32,
    positions: u32,
) -> Vec<BombeHit> {
    let per_middle = rings * positions;
    let per_reflector = middles * per_middle;
    let mut out = Vec::new();
    for triple in hits.as_chunks::<3>().0 {
        let score = f64::from(f32::from_bits(triple[0]));
        if !score.is_finite() || score < -1.0e29 {
            continue;
        }
        let index = triple[1];
        let within = index % per_reflector;
        let inner = within % per_middle;
        let p = inner % positions;
        out.push(BombeHit {
            score,
            order,
            reflector: (index / per_reflector) as usize,
            middle: Ring::new((within / per_middle) as u8),
            ring: Ring::new((inner / positions) as u8),
            positions: [
                Indicator::new((p / 676) as u8),
                Indicator::new(((p / 26) % 26) as u8),
                Indicator::new((p % 26) as u8),
            ],
            menu: (triple[2] / ALPHABET as u32) as usize,
            guess: (triple[2] % ALPHABET as u32) as u8,
        });
    }
    out
}

pub type PlacedMenu = (usize, Vec<(Letter, Letter)>, Letter);

fn pack_menus(menus: &[PlacedMenu], crib: usize) -> Vec<u32> {
    let mut packed: Vec<u32> = Vec::with_capacity(menus.len() * (crib * 2 + 29));
    for (offset, pairs, hub) in menus {
        let mut degree = [0u32; ALPHABET];
        for (p, c) in pairs {
            degree[*p as usize] += 1;
            degree[*c as usize] += 1;
        }
        let mut starts = [0u32; ALPHABET + 1];
        for l in 0..ALPHABET {
            starts[l + 1] = starts[l] + degree[l];
        }
        let mut at = starts;
        let mut flat = vec![0u32; pairs.len() * 2];
        for (i, (p, c)) in pairs.iter().enumerate() {
            for (from, to) in [(*p, *c), (*c, *p)] {
                flat[at[from as usize] as usize] = i as u32 | (u32::from(to) << 5);
                at[from as usize] += 1;
            }
        }
        packed.push(*offset as u32);
        packed.push(u32::from(*hub));
        packed.extend_from_slice(&starts);
        packed.extend_from_slice(&flat);
    }
    packed
}

pub struct BombeJob<'a> {
    pub ct: &'a [Letter],
    pub logp: &'a [f32],
    pub order: usize,
    pub orders: &'a [[usize; 3]],
    pub reflectors: &'a [[u8; ALPHABET]],
    pub menus: &'a [PlacedMenu],
    pub rings: usize,
    pub middles: usize,
    pub keep: usize,
}

#[derive(Clone, Debug)]
pub struct BombeFindings {
    pub best: Vec<BombeHit>,
    pub stops: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct BombeHit {
    pub score: f64,
    pub order: usize,
    pub reflector: usize,
    pub middle: Ring,
    pub ring: Ring,
    pub positions: [Indicator; 3],
    pub menu: usize,
    pub guess: Letter,
}

#[derive(Clone, Copy, Debug)]
pub struct EnigmaHit {
    pub score: f64,
    pub order: usize,
    pub reflector: usize,
    pub middle: Ring,
    pub ring: Ring,
    pub positions: [Indicator; 3],
}

fn compute_pipeline(
    device: &wgpu::Device,
    label: &str,
    source: &str,
    entry: &str,
    bindings: u32,
    read_only: u32,
) -> (wgpu::ComputePipeline, wgpu::BindGroupLayout) {
    let module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some(label),
        source: wgpu::ShaderSource::Wgsl(source.into()),
    });
    let entries: Vec<wgpu::BindGroupLayoutEntry> = (0..bindings)
        .map(|i| wgpu::BindGroupLayoutEntry {
            binding: i,
            visibility: wgpu::ShaderStages::COMPUTE,
            ty: wgpu::BindingType::Buffer {
                ty: wgpu::BufferBindingType::Storage {
                    read_only: i < read_only,
                },
                has_dynamic_offset: false,
                min_binding_size: None,
            },
            count: None,
        })
        .collect();
    let layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
        label: Some(label),
        entries: &entries,
    });
    let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
        label: Some(label),
        bind_group_layouts: &[&layout],
        push_constant_ranges: &[],
    });
    let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
        label: Some(label),
        layout: Some(&pipeline_layout),
        module: &module,
        entry_point: Some(entry),
        compilation_options: wgpu::PipelineCompilationOptions::default(),
        cache: None,
    });
    (pipeline, layout)
}

fn decode_hits(
    packed: &[u32],
    order: usize,
    rings: u32,
    middles: u32,
    positions: u32,
) -> Vec<EnigmaHit> {
    let per_middle = rings * positions;
    let per_reflector = middles * per_middle;
    packed
        .as_chunks::<2>()
        .0
        .iter()
        .filter_map(|&pair| {
            let score = f32::from_bits(pair[0]);
            if !score.is_finite() || score < -1.0e29 {
                return None;
            }
            let index = pair[1];
            let within = index % per_reflector;
            let inner = within % per_middle;
            let p = inner % positions;
            Some(EnigmaHit {
                score: f64::from(score),
                order,
                reflector: (index / per_reflector) as usize,
                middle: Ring::new((within / per_middle) as u8),
                ring: Ring::new((inner / positions) as u8),
                positions: [
                    Indicator::new((p / (ALPHABET as u32 * ALPHABET as u32)) as u8),
                    Indicator::new(((p / ALPHABET as u32) % ALPHABET as u32) as u8),
                    Indicator::new((p % ALPHABET as u32) as u8),
                ],
            })
        })
        .collect()
}

fn pack_enigma_tables(reflectors: &[[u8; ALPHABET]]) -> Vec<u32> {
    let (forward, backward, notches) = enigma::rotor_tables();
    let mut tables = vec![0u32; T_REFLECTOR + reflectors.len() * ALPHABET];
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
    tables
}

fn ct_words(ct: &[Letter]) -> Vec<u32> {
    ct.iter().map(|&l| u32::from(l)).collect()
}

pub struct Gpu {
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::ComputePipeline,
    layout: wgpu::BindGroupLayout,
    enigma_pipeline: wgpu::ComputePipeline,
    enigma_layout: wgpu::BindGroupLayout,
    plug_pipeline: wgpu::ComputePipeline,
    plug_layout: wgpu::BindGroupLayout,
    bombe_pipeline: wgpu::ComputePipeline,
    bombe_layout: wgpu::BindGroupLayout,
    pub name: String,
}

fn words_to_bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_ne_bytes()).collect()
}

fn floats_to_bytes(values: &[f32]) -> Vec<u8> {
    values.iter().flat_map(|v| v.to_ne_bytes()).collect()
}

fn widen(table: &[f32], langs: usize, padded: usize) -> Vec<f32> {
    let grams = table.len() / langs.max(1);
    let mut wide = vec![-1.0e30f32; grams * padded];
    for g in 0..grams {
        wide[g * padded..g * padded + langs].copy_from_slice(&table[g * langs..g * langs + langs]);
    }
    wide
}

fn spell_prefix(mut index: u64, len: usize) -> [u32; 16] {
    let mut prefix = [0u32; 16];
    for slot in prefix[..len].iter_mut().rev() {
        *slot = (index % ALPHABET as u64) as u32;
        index /= ALPHABET as u64;
    }
    prefix
}

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

fn params_for(
    n: usize,
    period: usize,
    padded: usize,
    order: usize,
    family: usize,
    count: u64,
    prefix: &[u32; 16],
) -> Vec<u32> {
    let prefix_len = period.saturating_sub(MAX_LOW_DIGITS);
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
    fn run_pass(
        &self,
        pipeline: &wgpu::ComputePipeline,
        bind: &wgpu::BindGroup,
        groups: u32,
        readbacks: &[(&wgpu::Buffer, &wgpu::Buffer)],
    ) {
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor::default());
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor::default());
            pass.set_pipeline(pipeline);
            pass.set_bind_group(0, bind, &[]);
            pass.dispatch_workgroups(groups, 1, 1);
        }
        for (from, to) in readbacks {
            encoder.copy_buffer_to_buffer(from, 0, to, 0, from.size());
        }
        self.queue.submit(Some(encoder.finish()));
    }

    fn bind(
        &self,
        label: &str,
        layout: &wgpu::BindGroupLayout,
        buffers: &[&wgpu::Buffer],
    ) -> wgpu::BindGroup {
        let entries: Vec<wgpu::BindGroupEntry> = buffers
            .iter()
            .enumerate()
            .map(|(i, buffer)| wgpu::BindGroupEntry {
                binding: i as u32,
                resource: buffer.as_entire_binding(),
            })
            .collect();
        self.device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some(label),
            layout,
            entries: &entries,
        })
    }

    /// # Errors
    /// Returns an error if GPU initialization fails.
    pub fn open() -> Result<Gpu, String> {
        let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor::default());
        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            ..Default::default()
        }))
        .map_err(|e| format!("no GPU adapter: {e}"))?;
        let name = adapter.get_info().name;
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
        let (enigma_pipeline, enigma_layout) =
            compute_pipeline(&device, "enigma", ENIGMA_SHADER, "sweep", 5, 4);
        let (plug_pipeline, plug_layout) =
            compute_pipeline(&device, "plugboard", PLUGBOARD_SHADER, "climb", 6, 5);
        let (bombe_pipeline, bombe_layout) =
            compute_pipeline(&device, "bombe", BOMBE_SHADER, "sweep", 7, 5);
        Ok(Gpu {
            device,
            queue,
            pipeline,
            layout,
            enigma_pipeline,
            enigma_layout,
            plug_pipeline,
            plug_layout,
            bombe_pipeline,
            bombe_layout,
            name,
        })
    }

    #[must_use]
    pub fn sweep_enigma(&self, job: &EnigmaJob) -> Vec<EnigmaHit> {
        let EnigmaJob {
            ct,
            logp,
            order,
            orders,
            reflectors,
            rings,
            middles,
            keep,
        } = *job;
        let tables = pack_enigma_tables(reflectors);

        let positions = (ALPHABET as u32).pow(3);
        let count = reflectors.len() as u32 * rings as u32 * positions;
        let chunk = count.div_ceil(THREADS);

        let ct_buffer = self.storage("ct", &words_to_bytes(&ct_words(ct)));
        let tables_buffer = self.storage("tables", &words_to_bytes(&tables));
        let logp_buffer = self.storage("logp", &floats_to_bytes(logp));
        let out_len = THREADS as usize * 2;
        let out_buffer = self.readable("out", (out_len * 4) as u64);
        let out_staging = self.staging("out-read", (out_len * 4) as u64);

        let keep = keep.max(1);
        let mut found: Vec<EnigmaHit> = Vec::new();
        for (o, rotors) in orders.iter().enumerate() {
            for middle in 0..middles as u32 {
                if middle >= 13 && enigma::notches_repeat_by_half_turn(rotors[1]) {
                    continue;
                }
                let params = vec![
                    ct.len() as u32,
                    count,
                    THREADS,
                    rings as u32,
                    1,
                    reflectors.len() as u32,
                    positions,
                    (ALPHABET as u32).pow(order as u32 - 1),
                    order as u32,
                    chunk,
                    rotors[0] as u32,
                    rotors[1] as u32,
                    rotors[2] as u32,
                    middle,
                ];
                let params_buffer = self.storage("params", &words_to_bytes(&params));
                let bind = self.bind(
                    "enigma",
                    &self.enigma_layout,
                    &[
                        &ct_buffer,
                        &tables_buffer,
                        &logp_buffer,
                        &params_buffer,
                        &out_buffer,
                    ],
                );
                let mut encoder = self
                    .device
                    .create_command_encoder(&wgpu::CommandEncoderDescriptor::default());
                {
                    let mut pass =
                        encoder.begin_compute_pass(&wgpu::ComputePassDescriptor::default());
                    pass.set_pipeline(&self.enigma_pipeline);
                    pass.set_bind_group(0, &bind, &[]);
                    pass.dispatch_workgroups(THREADS / WORKGROUP, 1, 1);
                }
                encoder.copy_buffer_to_buffer(
                    &out_buffer,
                    0,
                    &out_staging,
                    0,
                    (out_len * 4) as u64,
                );
                self.queue.submit(Some(encoder.finish()));

                let packed = bytes_to_words(&self.read(&out_staging));
                found.extend(
                    decode_hits(&packed, o, rings as u32, 1, positions)
                        .into_iter()
                        .map(|hit| EnigmaHit {
                            middle: Ring::new(middle as u8),
                            ..hit
                        }),
                );
                if found.len() > 2 * keep {
                    found.select_nth_unstable_by(keep, |a, b| b.score.total_cmp(&a.score));
                    found.truncate(keep);
                }
            }
        }
        found.sort_unstable_by(|a, b| b.score.total_cmp(&a.score));
        found.truncate(keep);
        found
    }

    #[must_use]
    pub fn sweep_bombe(&self, job: &BombeJob) -> BombeFindings {
        let BombeJob {
            ct,
            logp,
            order,
            orders,
            reflectors,
            menus,
            rings,
            middles,
            keep,
        } = *job;
        let crib = menus.first().map_or(0, |m| m.1.len());
        if crib == 0 || crib > BOMBE_MAX_CRIB || menus.iter().any(|m| m.1.len() != crib) {
            return BombeFindings {
                best: Vec::new(),
                stops: 0,
            };
        }
        let tables = pack_enigma_tables(reflectors);
        let packed = pack_menus(menus, crib);
        let reach = menus.iter().map(|m| m.0 + crib).max().unwrap_or(ct.len());

        let positions = (ALPHABET as u32).pow(3);
        let count = reflectors.len() as u32 * middles as u32 * rings as u32 * positions;
        let threads = THREADS.min(count);
        let chunk = count.div_ceil(threads);
        let groups = threads.div_ceil(BOMBE_WORKGROUP);

        let ct_buffer = self.storage("ct", &words_to_bytes(&ct_words(ct)));
        let tables_buffer = self.storage("tables", &words_to_bytes(&tables));
        let logp_buffer = self.storage("logp", &floats_to_bytes(logp));
        let menus_buffer = self.storage("menus", &words_to_bytes(&packed));
        let out_len = threads as usize * 3;
        let out_buffer = self.readable("out", (out_len * 4) as u64);
        let out_staging = self.staging("out-read", (out_len * 4) as u64);
        let stops_buffer = self.readable("stops", u64::from(threads) * 4);
        let stops_staging = self.staging("stops-read", u64::from(threads) * 4);

        let mut best: Vec<BombeHit> = Vec::new();
        let mut total: u64 = 0;
        for (o, rotors) in orders.iter().enumerate() {
            let params = vec![
                ct.len() as u32,
                count,
                threads,
                chunk,
                reflectors.len() as u32,
                positions,
                menus.len() as u32,
                crib as u32,
                (ALPHABET as u32).pow(order as u32 - 1),
                order as u32,
                rotors[0] as u32,
                rotors[1] as u32,
                rotors[2] as u32,
                rings as u32,
                middles as u32,
                reach as u32,
            ];
            let params_buffer = self.storage("params", &words_to_bytes(&params));
            let bind = self.bind(
                "bombe",
                &self.bombe_layout,
                &[
                    &ct_buffer,
                    &tables_buffer,
                    &logp_buffer,
                    &menus_buffer,
                    &params_buffer,
                    &out_buffer,
                    &stops_buffer,
                ],
            );
            self.run_pass(
                &self.bombe_pipeline,
                &bind,
                groups,
                &[(&out_buffer, &out_staging), (&stops_buffer, &stops_staging)],
            );

            let hits = bytes_to_words(&self.read(&out_staging));
            for found in bytes_to_words(&self.read(&stops_staging)) {
                total += u64::from(found);
            }
            best.extend(decode_stops(
                &hits,
                o,
                rings as u32,
                middles as u32,
                positions,
            ));
            best.sort_unstable_by(|a, b| b.score.total_cmp(&a.score));
            best.truncate(keep.max(1));
        }
        BombeFindings { best, stops: total }
    }

    #[must_use]
    pub fn climb_plugboards(
        &self,
        job: &EnigmaJob,
        candidates: &[EnigmaHit],
        leads: usize,
        margin: f32,
    ) -> Vec<(f64, [u8; ALPHABET])> {
        let EnigmaJob {
            ct,
            logp,
            order,
            orders: rotor_orders,
            reflectors,
            ..
        } = *job;
        if candidates.is_empty() {
            return Vec::new();
        }
        let tables = pack_enigma_tables(reflectors);

        let mut packed = Vec::with_capacity(candidates.len() * 9);
        for hit in candidates {
            let rotors = rotor_orders[hit.order];
            packed.push(rotors[0] as u32);
            packed.push(rotors[1] as u32);
            packed.push(rotors[2] as u32);
            packed.push(hit.reflector as u32);
            packed.push(u32::from(hit.middle.value()));
            packed.push(u32::from(hit.ring.value()));
            packed.push(u32::from(hit.positions[0].value()));
            packed.push(u32::from(hit.positions[1].value()));
            packed.push(u32::from(hit.positions[2].value()));
        }

        let threads = (candidates.len() as u32).div_ceil(WORKGROUP) * WORKGROUP;
        let params = vec![
            ct.len() as u32,
            candidates.len() as u32,
            threads,
            leads as u32,
            (ALPHABET as u32).pow(order as u32 - 1),
            order as u32,
            reflectors.len() as u32,
            margin.to_bits(),
        ];

        let ct_buffer = self.storage("ct", &words_to_bytes(&ct_words(ct)));
        let tables_buffer = self.storage("tables", &words_to_bytes(&tables));
        let logp_buffer = self.storage("logp", &floats_to_bytes(logp));
        let params_buffer = self.storage("params", &words_to_bytes(&params));
        let settings_buffer = self.storage("settings", &words_to_bytes(&packed));
        let out_len = candidates.len() * 6;
        let out_buffer = self.readable("out", (out_len * 4) as u64);
        let out_staging = self.staging("out-read", (out_len * 4) as u64);

        let bind = self.bind(
            "plugboard",
            &self.plug_layout,
            &[
                &ct_buffer,
                &tables_buffer,
                &logp_buffer,
                &params_buffer,
                &settings_buffer,
                &out_buffer,
            ],
        );
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor::default());
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor::default());
            pass.set_pipeline(&self.plug_pipeline);
            pass.set_bind_group(0, &bind, &[]);
            pass.dispatch_workgroups(threads / WORKGROUP, 1, 1);
        }
        encoder.copy_buffer_to_buffer(&out_buffer, 0, &out_staging, 0, (out_len * 4) as u64);
        self.queue.submit(Some(encoder.finish()));

        let words = bytes_to_words(&self.read(&out_staging));
        words
            .as_chunks::<6>()
            .0
            .iter()
            .map(|&c| {
                let score = f64::from(f32::from_bits(c[0]));
                let mut board = [0u8; ALPHABET];
                for (i, slot) in board.iter_mut().enumerate() {
                    let word = c[1 + i / 6];
                    *slot = ((word >> ((i % 6) * 5)) & 31) as u8;
                }
                (score, board)
            })
            .collect()
    }

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

        let ct_buffer = self.storage("ct", &words_to_bytes(&ct_words(ct)));
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

    fn dispatch(
        &self,
        ct: &wgpu::Buffer,
        table: &wgpu::Buffer,
        params: &wgpu::Buffer,
        out: &wgpu::Buffer,
        staging: &wgpu::Buffer,
        out_len: usize,
    ) {
        let bind = self.bind("periodic", &self.layout, &[ct, table, params, out]);
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
    fn the_table_offsets_match_the_ones_the_shaders_use() {
        assert_eq!(T_FORWARD, 0);
        assert_eq!(T_BACKWARD, 208);
        assert_eq!(T_NOTCH, 416);
        assert_eq!(T_REFLECTOR, 424);
        assert!(ENIGMA_SHADER.contains("const BACKWARD: u32 = 208u;"));
        assert!(ENIGMA_SHADER.contains("const NOTCH: u32 = 416u;"));
        assert!(ENIGMA_SHADER.contains("const REFLECTOR: u32 = 424u;"));
        assert!(PLUGBOARD_SHADER.contains("const BACKWARD: u32 = 208u;"));
        assert!(PLUGBOARD_SHADER.contains("const REFLECTOR: u32 = 424u;"));
    }

    #[test]
    fn the_shaders_size_their_shared_tables_for_the_real_ones() {
        let reflector_words = enigma::NAVAL_REFLECTOR_COUNT * ALPHABET;
        assert_eq!(reflector_words, 2704);
        for shader in [ENIGMA_SHADER, PLUGBOARD_SHADER] {
            assert!(shader.contains("array<u32, 2704>"), "reflector table size");
            assert!(shader.contains("array<u32, 208>"), "rotor table size");
        }
    }

    #[test]
    fn opening_a_device_either_works_or_says_why() {
        match Gpu::open() {
            Ok(gpu) => assert!(!gpu.name.is_empty()),
            Err(message) => assert!(!message.is_empty()),
        }
    }
}
