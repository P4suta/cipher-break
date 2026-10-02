// SPDX-License-Identifier: MIT OR Apache-2.0

struct Params {
    n: u32,
    period: u32,
    langs: u32,
    order: u32,
    modulus: u32,
    family: u32,
    count: u32,
    threads: u32,
    prefix_len: u32,
    vec_per_gram: u32,
    pad0: u32,
    pad1: u32,
    prefix: array<u32, 16>,
};

@group(0) @binding(0) var<storage, read> ct: array<u32>;
@group(0) @binding(1) var<storage, read> table: array<vec4<f32>>;
@group(0) @binding(2) var<storage, read> params: Params;
@group(0) @binding(3) var<storage, read_write> out: array<u32>;

const NEG: f32 = -1.0e30;

fn digit(k0: u32, k1: u32, k2: u32, i: u32) -> u32 {
    let w = i / 6u;
    let sh = (i % 6u) * 5u;
    var word = k0;
    if (w == 1u) { word = k1; } else if (w == 2u) { word = k2; }
    return (word >> sh) & 31u;
}

@compute @workgroup_size(256)
fn sweep(@builtin(global_invocation_id) gid: vec3<u32>) {
    let tid = gid.x;
    if (tid >= params.threads) {
        return;
    }

    let n = params.n;
    let period = params.period;
    let vpg = params.vec_per_gram;
    let modulus = params.modulus;

    var best: f32 = NEG;
    var best_index: u32 = 0u;

    var i: u32 = tid;
    loop {
        if (i >= params.count) {
            break;
        }

        var k0: u32 = 0u;
        var k1: u32 = 0u;
        var k2: u32 = 0u;
        var rest: u32 = i;
        var d: u32 = period;
        loop {
            if (d <= params.prefix_len) { break; }
            d = d - 1u;
            let v = rest % 26u;
            rest = rest / 26u;
            let w = d / 6u;
            let sh = (d % 6u) * 5u;
            if (w == 0u) { k0 = k0 | (v << sh); }
            else if (w == 1u) { k1 = k1 | (v << sh); }
            else { k2 = k2 | (v << sh); }
        }
        for (var j: u32 = 0u; j < params.prefix_len; j = j + 1u) {
            let v = params.prefix[j];
            let w = j / 6u;
            let sh = (j % 6u) * 5u;
            if (w == 0u) { k0 = k0 | (v << sh); }
            else if (w == 1u) { k1 = k1 | (v << sh); }
            else { k2 = k2 | (v << sh); }
        }

        var a0 = vec4<f32>(0.0);
        var a1 = vec4<f32>(0.0);
        var a2 = vec4<f32>(0.0);
        var a3 = vec4<f32>(0.0);
        var a4 = vec4<f32>(0.0);

        var g: u32 = 0u;
        var ki: u32 = 0u;
        var grams: u32 = 0u;

        for (var pos: u32 = 0u; pos < n; pos = pos + 1u) {
            let k = digit(k0, k1, k2, ki);
            ki = ki + 1u;
            if (ki == period) { ki = 0u; }

            let c = ct[pos];
            var p: u32;
            if (params.family == 0u) {
                p = (c + 26u - k) % 26u;
            } else if (params.family == 1u) {
                p = (k + 26u - c) % 26u;
            } else {
                p = (c + k) % 26u;
            }

            g = (g % modulus) * 26u + p;

            if (pos + 1u >= params.order) {
                let row = g * vpg;
                a0 = a0 + table[row];
                if (vpg > 1u) { a1 = a1 + table[row + 1u]; }
                if (vpg > 2u) { a2 = a2 + table[row + 2u]; }
                if (vpg > 3u) { a3 = a3 + table[row + 3u]; }
                if (vpg > 4u) { a4 = a4 + table[row + 4u]; }
                grams = grams + 1u;
            }
        }

        let m0 = max(max(a0.x, a0.y), max(a0.z, a0.w));
        let m1 = max(max(a1.x, a1.y), max(a1.z, a1.w));
        let m2 = max(max(a2.x, a2.y), max(a2.z, a2.w));
        let m3 = max(max(a3.x, a3.y), max(a3.z, a3.w));
        let m4 = max(max(a4.x, a4.y), max(a4.z, a4.w));
        let m = max(max(max(m0, m1), max(m2, m3)), m4);

        let s = m / f32(max(grams, 1u));
        if (s > best) {
            best = s;
            best_index = i;
        }

        i = i + params.threads;
    }

    out[tid * 2u] = bitcast<u32>(best);
    out[tid * 2u + 1u] = best_index;
}
