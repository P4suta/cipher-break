// SPDX-License-Identifier: MIT OR Apache-2.0

struct Params {
    n: u32,
    candidates: u32,
    threads: u32,
    leads: u32,
    modulus: u32,
    order: u32,
    reflectors: u32,
    margin_bits: u32,
};

@group(0) @binding(0) var<storage, read> ct: array<u32>;
@group(0) @binding(1) var<storage, read> tables: array<u32>;
@group(0) @binding(2) var<storage, read> logp: array<f32>;
@group(0) @binding(3) var<storage, read> params: Params;
@group(0) @binding(4) var<storage, read> settings: array<u32>;
@group(0) @binding(5) var<storage, read_write> out: array<u32>;

const FORWARD: u32 = 0u;
const BACKWARD: u32 = 208u;
const NOTCH: u32 = 416u;
const REFLECTOR: u32 = 424u;

var<workgroup> w_forward: array<u32, 208>;
var<workgroup> w_backward: array<u32, 208>;
var<workgroup> w_notch: array<u32, 8>;
var<workgroup> w_reflector: array<u32, 2704>;

fn plug(board: ptr<function, array<u32, 5>>, i: u32) -> u32 {
    let w = i / 6u;
    let sh = (i % 6u) * 5u;
    return ((*board)[w] >> sh) & 31u;
}

fn plug_put(board: ptr<function, array<u32, 5>>, i: u32, v: u32) {
    let w = i / 6u;
    let sh = (i % 6u) * 5u;
    (*board)[w] = ((*board)[w] & ~(31u << sh)) | (v << sh);
}

fn identity_board(board: ptr<function, array<u32, 5>>) {
    for (var i = 0u; i < 5u; i = i + 1u) { (*board)[i] = 0u; }
    for (var i = 0u; i < 26u; i = i + 1u) { plug_put(board, i, i); }
}

fn connect(board: ptr<function, array<u32, 5>>, a: u32, b: u32) {
    let oa = plug(board, a);
    let ob = plug(board, b);
    plug_put(board, oa, oa);
    plug_put(board, ob, ob);
    plug_put(board, a, b);
    plug_put(board, b, a);
}

fn leads_used(board: ptr<function, array<u32, 5>>) -> u32 {
    var count = 0u;
    for (var i = 0u; i < 26u; i = i + 1u) {
        if (plug(board, i) > i) { count = count + 1u; }
    }
    return count;
}

fn through_forward(rotor: u32, c: u32, pos: u32) -> u32 {
    return (w_forward[rotor * 26u + (c + pos) % 26u] + 26u - pos) % 26u;
}

fn through_backward(rotor: u32, c: u32, pos: u32) -> u32 {
    return (w_backward[rotor * 26u + (c + pos) % 26u] + 26u - pos) % 26u;
}

fn score(
    board: ptr<function, array<u32, 5>>,
    r0: u32, r1: u32, r2: u32, refl: u32, middle: u32, ring: u32,
    q0: u32, q1: u32, q2: u32,
) -> f32 {
    var p0 = q0;
    var p1 = q1;
    var p2 = q2;
    var acc = 0.0;
    var g = 0u;
    var grams = 0u;
    for (var i = 0u; i < params.n; i = i + 1u) {
        let middle_notch = (w_notch[r1] >> p1) & 1u;
        let right_notch = (w_notch[r2] >> p2) & 1u;
        if (middle_notch == 1u) {
            p1 = (p1 + 1u) % 26u;
            p0 = (p0 + 1u) % 26u;
        } else if (right_notch == 1u) {
            p1 = (p1 + 1u) % 26u;
        }
        p2 = (p2 + 1u) % 26u;

        let s2 = (p2 + 26u - ring) % 26u;
        let s1 = (p1 + 26u - middle) % 26u;
        var c = plug(board, ct[i]);
        c = through_forward(r2, c, s2);
        c = through_forward(r1, c, s1);
        c = through_forward(r0, c, p0);
        c = w_reflector[refl + c];
        c = through_backward(r0, c, p0);
        c = through_backward(r1, c, s1);
        c = through_backward(r2, c, s2);
        c = plug(board, c);

        g = (g % params.modulus) * 26u + c;
        if (i + 1u >= params.order) {
            acc = acc + logp[g];
            grams = grams + 1u;
        }
    }
    return acc / f32(max(grams, 1u));
}

@compute @workgroup_size(256)
fn climb(@builtin(global_invocation_id) gid: vec3<u32>, @builtin(local_invocation_id) lid: vec3<u32>) {
    for (var i = lid.x; i < 208u; i = i + 256u) {
        w_forward[i] = tables[FORWARD + i];
        w_backward[i] = tables[BACKWARD + i];
    }
    for (var i = lid.x; i < 8u; i = i + 256u) { w_notch[i] = tables[NOTCH + i]; }
    for (var i = lid.x; i < 2704u; i = i + 256u) { w_reflector[i] = tables[REFLECTOR + i]; }
    workgroupBarrier();

    let tid = gid.x;
    if (tid >= params.candidates) { return; }

    let base = tid * 9u;
    let r0 = settings[base];
    let r1 = settings[base + 1u];
    let r2 = settings[base + 2u];
    let refl = settings[base + 3u] * 26u;
    let middle = settings[base + 4u];
    let ring = settings[base + 5u];
    let q0 = settings[base + 6u];
    let q1 = settings[base + 7u];
    let q2 = settings[base + 8u];

    var board: array<u32, 5>;
    identity_board(&board);
    var best = score(&board, r0, r1, r2, refl, middle, ring, q0, q1, q2);
    let margin = bitcast<f32>(params.margin_bits);

    for (var round = 0u; round < params.leads; round = round + 1u) {
        var found = false;
        var best_a = 0u;
        var best_b = 0u;
        for (var a = 0u; a < 26u; a = a + 1u) {
            for (var b = a + 1u; b < 26u; b = b + 1u) {
                var trial = board;
                connect(&trial, a, b);
                if (leads_used(&trial) > params.leads) { continue; }
                let s = score(&trial, r0, r1, r2, refl, middle, ring, q0, q1, q2);
                if (s > best + margin) {
                    best = s;
                    best_a = a;
                    best_b = b;
                    found = true;
                }
            }
        }
        if (!found) { break; }
        connect(&board, best_a, best_b);
    }

    let slot = tid * 6u;
    out[slot] = bitcast<u32>(best);
    for (var i = 0u; i < 5u; i = i + 1u) { out[slot + 1u + i] = board[i]; }
}
