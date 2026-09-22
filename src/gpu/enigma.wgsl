// SPDX-License-Identifier: MIT OR Apache-2.0
//
// An Enigma rotor sweep, one setting per iteration and many iterations per
// thread.
//
// Everything the inner loop touches lives in workgroup memory: the eight rotor
// wirings both ways, their notches, and all 104 naval reflectors come to about
// fourteen kilobytes, which fits with room to spare and is an order of
// magnitude faster to read than the device memory they arrive in. Only the
// language table is left outside, because seventy kilobytes will not fit and
// it is read once per letter rather than seven times.
//
// Work is handed out in contiguous blocks rather than strides, so a thread
// walks the starting positions of one rotor order with everything else fixed.
// That is the arrangement the caches like and the one the machine likes: the
// rotors only need re-reading when the block moves on.

struct Params {
    n: u32,
    count: u32,          // settings in this dispatch
    threads: u32,
    orders: u32,         // how many rotor orders
    reflectors: u32,     // how many reflectors
    positions: u32,      // 26^3
    modulus: u32,        // 26^(order-1)
    order: u32,          // n-gram order
    chunk: u32,          // settings per thread
    pad0: u32,
    pad1: u32,
    pad2: u32,
};

// Packed once by the host: 8*26 forward, 8*26 backward, 8 notch masks,
// 104*26 reflectors, then 3 rotor indices per order.
@group(0) @binding(0) var<storage, read> ct: array<u32>;
@group(0) @binding(1) var<storage, read> tables: array<u32>;
@group(0) @binding(2) var<storage, read> logp: array<f32>;
@group(0) @binding(3) var<storage, read> params: Params;
@group(0) @binding(4) var<storage, read_write> out: array<u32>;

const FORWARD: u32 = 0u;
const BACKWARD: u32 = 208u;
const NOTCH: u32 = 416u;
const REFLECTOR: u32 = 424u;
const ORDERS: u32 = 424u + 104u * 26u;

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

@compute @workgroup_size(256)
fn sweep(@builtin(global_invocation_id) gid: vec3<u32>, @builtin(local_invocation_id) lid: vec3<u32>) {
    // Fill the shared tables once per workgroup.
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

    let per_order = params.reflectors * params.positions;
    var cached_order: u32 = 0xFFFFFFFFu;
    var r0: u32 = 0u;
    var r1: u32 = 0u;
    var r2: u32 = 0u;

    for (var index = start; index < stop; index = index + 1u) {
        let o = index / per_order;
        if (o != cached_order) {
            cached_order = o;
            r0 = tables[ORDERS + o * 3u];
            r1 = tables[ORDERS + o * 3u + 1u];
            r2 = tables[ORDERS + o * 3u + 2u];
        }
        let within = index % per_order;
        let refl = (within / params.positions) * 26u;
        let p = within % params.positions;

        var p0 = p / 676u;
        var p1 = (p / 26u) % 26u;
        var p2 = p % 26u;

        var acc: f32 = 0.0;
        var g: u32 = 0u;
        var grams: u32 = 0u;

        for (var i: u32 = 0u; i < params.n; i = i + 1u) {
            // Step, including the double step a middle rotor on its own notch
            // takes.
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
            c = through_forward(r2, c, p2);
            c = through_forward(r1, c, p1);
            c = through_forward(r0, c, p0);
            c = w_reflector[refl + c];
            c = through_backward(r0, c, p0);
            c = through_backward(r1, c, p1);
            c = through_backward(r2, c, p2);

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
