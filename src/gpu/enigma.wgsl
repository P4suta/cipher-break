// SPDX-License-Identifier: MIT OR Apache-2.0

struct Params {
    n: u32,
    count: u32,
    threads: u32,
    rings: u32,
    middles: u32,
    reflectors: u32,
    positions: u32,
    modulus: u32,
    order: u32,
    chunk: u32,
    r0: u32,
    r1: u32,
    r2: u32,
    middle_base: u32,
};

@group(0) @binding(0) var<storage, read> ct: array<u32>;
@group(0) @binding(1) var<storage, read> tables: array<u32>;
@group(0) @binding(2) var<storage, read> logp: array<f32>;
@group(0) @binding(3) var<storage, read> params: Params;
@group(0) @binding(4) var<storage, read_write> out: array<u32>;

const FORWARD: u32 = 0u;
const BACKWARD: u32 = 208u;
const NOTCH: u32 = 416u;
const REFLECTOR: u32 = 424u;

var<workgroup> w_forward: array<u32, 208>;
var<workgroup> w_backward: array<u32, 208>;
var<workgroup> w_notch: array<u32, 8>;
var<workgroup> w_reflector: array<u32, 2704>;

fn through_forward(rotor: u32, c: u32, pos: u32) -> u32 {
    let entered = (c + pos) % 26u;
    return (w_forward[rotor * 26u + entered] + 26u - pos) % 26u;
}

fn through_backward(rotor: u32, c: u32, pos: u32) -> u32 {
    let entered = (c + pos) % 26u;
    return (w_backward[rotor * 26u + entered] + 26u - pos) % 26u;
}

fn rotl26(mask: u32, by: u32) -> u32 {
    return ((mask << by) | (mask >> (26u - by))) & 0x3ffffffu;
}

fn rotr26(mask: u32, by: u32) -> u32 {
    return ((mask >> by) | (mask << (26u - by))) & 0x3ffffffu;
}

fn middle_touches(notch1: u32, notch2: u32, q1: u32, q2: u32, ring: u32, length: u32) -> bool {
    if (length == 0u) {
        return false;
    }
    let steps = length - 1u;
    let from_right = rotr26(notch2, q2);
    let partial = steps % 26u;
    let turns = (steps / 26u) * countOneBits(notch2)
        + countOneBits(from_right & ((1u << partial) - 1u));
    var passed = 0x3ffffffu;
    if (turns < 25u) {
        passed = rotl26((1u << (turns + 1u)) - 1u, q1);
    }
    return (passed & (notch1 | rotl26(notch1, ring))) != 0u;
}

fn half_turn(mask: u32) -> bool {
    return (((mask << 13u) | (mask >> 13u)) & 0x3ffffffu) == mask;
}

@compute @workgroup_size(256)
fn sweep(@builtin(global_invocation_id) gid: vec3<u32>, @builtin(local_invocation_id) lid: vec3<u32>) {
    for (var i = lid.x; i < 208u; i = i + 256u) {
        w_forward[i] = tables[FORWARD + i];
        w_backward[i] = tables[BACKWARD + i];
    }
    for (var i = lid.x; i < 8u; i = i + 256u) {
        w_notch[i] = tables[NOTCH + i];
    }
    for (var i = lid.x; i < 2704u; i = i + 256u) {
        w_reflector[i] = tables[REFLECTOR + i];
    }
    workgroupBarrier();

    let tid = gid.x;
    if (tid >= params.threads) {
        return;
    }

    var best: f32 = -1.0e30;
    var best_index: u32 = 0u;

    let start = tid * params.chunk;
    var stop = start + params.chunk;
    if (stop > params.count) { stop = params.count; }

    let r0 = params.r0;
    let r1 = params.r1;
    let r2 = params.r2;
    let per_middle = params.rings * params.positions;
    let per_reflector = params.middles * per_middle;

    let half_right = half_turn(w_notch[r2]);
    let half_middle = half_turn(w_notch[r1]);

    for (var index = start; index < stop; index = index + 1u) {
        let refl = (index / per_reflector) * 26u;
        let within = index % per_reflector;
        let middle = params.middle_base + within / per_middle;
        let inner = within % per_middle;
        let ring = inner / params.positions;
        let p = inner % params.positions;

        var p0 = p / 676u;
        var p1 = (p / 26u) % 26u;
        var p2 = p % 26u;

        if ((ring >= 13u && half_right) || (middle >= 13u && half_middle)) {
            continue;
        }

        if (middle != 0u && !middle_touches(w_notch[r1], w_notch[r2], p1, p2, middle, params.n)) {
            continue;
        }

        var acc: f32 = 0.0;
        var g: u32 = 0u;
        var grams: u32 = 0u;

        for (var i: u32 = 0u; i < params.n; i = i + 1u) {
            let middle_notch = (w_notch[r1] >> p1) & 1u;
            let right_notch = (w_notch[r2] >> p2) & 1u;
            if (middle_notch == 1u) {
                p1 = (p1 + 1u) % 26u;
                p0 = (p0 + 1u) % 26u;
            } else if (right_notch == 1u) {
                p1 = (p1 + 1u) % 26u;
            }
            p2 = (p2 + 1u) % 26u;

            var c = ct[i];
            let s2 = (p2 + 26u - ring) % 26u;
            let s1 = (p1 + 26u - middle) % 26u;
            c = through_forward(r2, c, s2);
            c = through_forward(r1, c, s1);
            c = through_forward(r0, c, p0);
            c = w_reflector[refl + c];
            c = through_backward(r0, c, p0);
            c = through_backward(r1, c, s1);
            c = through_backward(r2, c, s2);

            g = (g % params.modulus) * 26u + c;
            if (i + 1u >= params.order) {
                acc = acc + logp[g];
                grams = grams + 1u;
            }
        }

        let s = acc / f32(max(grams, 1u));
        if (s > best) {
            best = s;
            best_index = index;
        }
    }

    out[tid * 2u] = bitcast<u32>(best);
    out[tid * 2u + 1u] = best_index;
}
