// SPDX-License-Identifier: MIT OR Apache-2.0

struct Params {
    n: u32,
    count: u32,
    threads: u32,
    chunk: u32,
    reflectors: u32,
    positions: u32,
    menus: u32,
    crib: u32,
    modulus: u32,
    order: u32,
    r0: u32,
    r1: u32,
    r2: u32,
    rings: u32,
    middles: u32,
    reach: u32,
};

@group(0) @binding(0) var<storage, read> ct: array<u32>;
@group(0) @binding(1) var<storage, read> tables: array<u32>;
@group(0) @binding(2) var<storage, read> logp: array<f32>;
@group(0) @binding(3) var<storage, read> menus: array<u32>;
@group(0) @binding(4) var<storage, read> params: Params;
@group(0) @binding(5) var<storage, read_write> out: array<u32>;
@group(0) @binding(6) var<storage, read_write> stops: array<u32>;

const FORWARD: u32 = 0u;
const BACKWARD: u32 = 208u;
const NOTCH: u32 = 416u;
const REFLECTOR: u32 = 424u;
const THREADS_PER_GROUP: u32 = 128u;
const NONE: u32 = 31u;
const ALL: u32 = 0x3ffffffu;

var<workgroup> w_forward: array<u32, 208>;
var<workgroup> w_backward: array<u32, 208>;
var<workgroup> w_notch: array<u32, 8>;

fn wrap(x: u32) -> u32 {
    return select(x, x - 26u, x >= 26u);
}

fn through_forward(rotor: u32, c: u32, pos: u32) -> u32 {
    let entered = wrap(c + pos);
    return wrap(w_forward[rotor * 26u + entered] + 26u - pos);
}

fn through_backward(rotor: u32, c: u32, pos: u32) -> u32 {
    let entered = wrap(c + pos);
    return wrap(w_backward[rotor * 26u + entered] + 26u - pos);
}

struct Board {
    known: u32,
    v0: u32,
    v1: u32,
    v2: u32,
    v3: u32,
    v4: u32,
};

fn board_get(b: Board, l: u32) -> u32 {
    let word = l / 6u;
    let shift = (l % 6u) * 5u;
    var w = select(b.v4, b.v3, word == 3u);
    w = select(w, b.v2, word == 2u);
    w = select(w, b.v1, word == 1u);
    w = select(w, b.v0, word == 0u);
    return (w >> shift) & 31u;
}

fn board_set(b: Board, l: u32, v: u32) -> Board {
    let word = l / 6u;
    let shift = (l % 6u) * 5u;
    let mask = ~(31u << shift);
    let bits = (v & 31u) << shift;
    return Board(
        b.known | (1u << l),
        select(b.v0, (b.v0 & mask) | bits, word == 0u),
        select(b.v1, (b.v1 & mask) | bits, word == 1u),
        select(b.v2, (b.v2 & mask) | bits, word == 2u),
        select(b.v3, (b.v3 & mask) | bits, word == 3u),
        select(b.v4, (b.v4 & mask) | bits, word == 4u),
    );
}

const TRACE_WORDS: u32 = 16u;
var<workgroup> w_trace: array<u32, 2048>;

fn trace_put(lane: u32, i: u32, p0: u32, p1: u32, p2: u32) {
    let packed = p0 | (p1 << 5u) | (p2 << 10u);
    let word = i / 2u;
    let shift = (i % 2u) * 15u;
    let at = word * THREADS_PER_GROUP + lane;
    let mask = ~(32767u << shift);
    w_trace[at] = (w_trace[at] & mask) | (packed << shift);
}

fn trace_get(lane: u32, i: u32) -> vec3<u32> {
    let word = i / 2u;
    let shift = (i % 2u) * 15u;
    let packed = (w_trace[word * THREADS_PER_GROUP + lane] >> shift) & 32767u;
    return vec3<u32>(packed & 31u, (packed >> 5u) & 31u, (packed >> 10u) & 31u);
}

fn machine_at(lane: u32, i: u32, l: u32, refl: u32) -> u32 {
    let p = trace_get(lane, i);
    var c = l;
    c = through_forward(params.r2, c, p.z);
    c = through_forward(params.r1, c, p.y);
    c = through_forward(params.r0, c, p.x);
    c = tables[REFLECTOR + refl + c];
    c = through_backward(params.r0, c, p.x);
    c = through_backward(params.r1, c, p.y);
    c = through_backward(params.r2, c, p.z);
    return c;
}

struct Settled {
    board: Board,
    reached: u32,
    ok: bool,
};

fn settle(b: Board, a: u32, x: u32) -> Settled {
    var out = Settled(b, 0u, true);
    for (var k: u32 = 0u; k < 2u; k = k + 1u) {
        var end = a;
        var other = x;
        if (k == 1u) { end = x; other = a; }
        if (((out.board.known >> end) & 1u) == 1u) {
            if (board_get(out.board, end) != other) {
                out.ok = false;
                return out;
            }
        } else {
            out.board = board_set(out.board, end, other);
            out.reached = out.reached | (1u << end);
        }
    }
    return out;
}

struct Followed {
    board: Board,
    ok: bool,
};

fn follow(lane: u32, base: u32, refl: u32, hub: u32, guess: u32) -> Followed {
    var b = Board(0u, 0u, 0u, 0u, 0u, 0u);
    let first = settle(b, hub, guess);
    if (!first.ok) {
        return Followed(b, false);
    }
    b = first.board;
    var frontier = first.reached;

    while (frontier != 0u) {
        var next: u32 = 0u;
        var rest = frontier;
        while (rest != 0u) {
            let l = firstTrailingBit(rest);
            rest = rest & (rest - 1u);
            let u = board_get(b, l);
            let first = menus[base + 2u + l];
            let last = menus[base + 3u + l];
            for (var e: u32 = first; e < last; e = e + 1u) {
                let pair = menus[base + 29u + e];
                let at = pair & 31u;
                let to = (pair >> 5u) & 31u;
                let v = machine_at(lane, at, u, refl);
                if (((b.known >> to) & 1u) == 1u) {
                    if (board_get(b, to) != v) {
                        return Followed(b, false);
                    }
                } else {
                    let s = settle(b, to, v);
                    if (!s.ok) {
                        return Followed(b, false);
                    }
                    b = s.board;
                    next = next | s.reached;
                }
            }
        }
        frontier = next;
    }
    return Followed(b, true);
}

fn turns_within(mask: u32, at: u32, length: u32) -> bool {
    if (length >= 26u) {
        return mask != 0u;
    }
    let turned = ((mask >> at) | (mask << (26u - at))) & 0x3ffffffu;
    return (turned & ((1u << length) - 1u)) != 0u;
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

@compute @workgroup_size(128)
fn sweep(@builtin(global_invocation_id) gid: vec3<u32>, @builtin(local_invocation_id) lid: vec3<u32>) {
    for (var i = lid.x; i < 208u; i = i + THREADS_PER_GROUP) {
        w_forward[i] = tables[FORWARD + i];
        w_backward[i] = tables[BACKWARD + i];
    }
    for (var i = lid.x; i < 8u; i = i + THREADS_PER_GROUP) {
        w_notch[i] = tables[NOTCH + i];
    }
    workgroupBarrier();

    let tid = gid.x;
    if (tid >= params.threads) { return; }
    let lane = lid.x;

    var best: f32 = -1.0e30;
    var best_index: u32 = 0u;
    var best_stop: u32 = 0u;
    var found: u32 = 0u;
    let per_middle = params.rings * params.positions;
    let per_reflector = params.middles * per_middle;

    let start = tid * params.chunk;
    var stop = start + params.chunk;
    if (stop > params.count) { stop = params.count; }

    let half_right = half_turn(w_notch[params.r2]);
    let half_middle = half_turn(w_notch[params.r1]);

    for (var index = start; index < stop; index = index + 1u) {
        let refl = (index / per_reflector) * 26u;
        let within = index % per_reflector;
        let middle = within / per_middle;
        let inner = within % per_middle;
        let ring = inner / params.positions;
        let p = inner % params.positions;

        if ((ring >= 13u && half_right) || (middle >= 13u && half_middle)) {
            continue;
        }

        let right_indicator = p % 26u;
        if (!turns_within(w_notch[params.r2], right_indicator, params.reach)) {
            let wiring = (right_indicator + 26u - ring) % 26u;
            var first = 0u;
            for (var r: u32 = 0u; r < 26u; r = r + 1u) {
                if (!turns_within(w_notch[params.r2], (wiring + r) % 26u, params.reach)) {
                    first = r;
                    break;
                }
            }
            if (ring != first) {
                continue;
            }
        }

        if (middle != 0u && !middle_touches(w_notch[params.r1], w_notch[params.r2], (p / 26u) % 26u, p % 26u, middle, params.reach)) {
            continue;
        }

        for (var m: u32 = 0u; m < params.menus; m = m + 1u) {
            let base = m * (params.crib * 2u + 29u);
            let offset = menus[base];
            let hub = menus[base + 1u];

            var p0 = p / 676u;
            var p1 = (p / 26u) % 26u;
            var p2 = p % 26u;
            for (var i: u32 = 0u; i < offset + params.crib; i = i + 1u) {
                let middle_notch = (w_notch[params.r1] >> p1) & 1u;
                let right_notch = (w_notch[params.r2] >> p2) & 1u;
                if (middle_notch == 1u) {
                    p1 = wrap(p1 + 1u);
                    p0 = wrap(p0 + 1u);
                } else if (right_notch == 1u) {
                    p1 = wrap(p1 + 1u);
                }
                p2 = wrap(p2 + 1u);
                if (i >= offset) {
                    trace_put(lane, i - offset, p0, wrap(p1 + 26u - middle), wrap(p2 + 26u - ring));
                }
            }

            for (var guess: u32 = 0u; guess < 26u; guess = guess + 1u) {
                let r = follow(lane, base, refl, hub, guess);
                if (!r.ok) { continue; }
                found = found + 1u;

                var q0 = p / 676u;
                var q1 = (p / 26u) % 26u;
                var q2 = p % 26u;
                var acc: f32 = 0.0;
                var g: u32 = 0u;
                var grams: u32 = 0u;
                for (var i: u32 = 0u; i < params.n; i = i + 1u) {
                    let middle_notch = (w_notch[params.r1] >> q1) & 1u;
                    let right_notch = (w_notch[params.r2] >> q2) & 1u;
                    if (middle_notch == 1u) {
                        q1 = wrap(q1 + 1u);
                        q0 = wrap(q0 + 1u);
                    } else if (right_notch == 1u) {
                        q1 = wrap(q1 + 1u);
                    }
                    q2 = wrap(q2 + 1u);

                    let s1 = wrap(q1 + 26u - middle);
                    let s2 = wrap(q2 + 26u - ring);
                    var c = ct[i];
                    if (((r.board.known >> c) & 1u) == 1u) { c = board_get(r.board, c); }
                    c = through_forward(params.r2, c, s2);
                    c = through_forward(params.r1, c, s1);
                    c = through_forward(params.r0, c, q0);
                    c = tables[REFLECTOR + refl + c];
                    c = through_backward(params.r0, c, q0);
                    c = through_backward(params.r1, c, s1);
                    c = through_backward(params.r2, c, s2);
                    if (((r.board.known >> c) & 1u) == 1u) { c = board_get(r.board, c); }

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
                    best_stop = m * 26u + guess;
                }
                break;
            }
        }
    }

    out[tid * 3u] = bitcast<u32>(best);
    out[tid * 3u + 1u] = best_index;
    out[tid * 3u + 2u] = best_stop;
    stops[tid] = found;
}
