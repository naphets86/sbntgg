import random, math, ipaddress, itertools, sys
from fractions import Fraction
from src.models import Group, PlanConfig, PlanError
from src.planner import plan_subnets, prefix_for, required_addresses

random.seed(1)
# 1 prefix_for
for r in range(1, 20000):
    p = prefix_for(r, 32, "x") if r <= 2**32 else None
    k = math.ceil(math.log2(r)) if r > 1 else 0
    assert p == 32 - k, r
    assert 2**(32-p) >= r and (r == 1 or 2**(32-p-1) < r)
print("prefix_for ok")

def rnd_cfg(strategy, gw, v6=False):
    n = random.randint(1, 12)
    gs = tuple(Group(f"g{i}", random.choice([1,2,5,10,30,60,120,250,500,1000,4000]), None, (), random.randint(0,3)) for i in range(n))
    base = ipaddress.ip_network("2001:db8::/48" if v6 else random.choice(["10.0.0.0/16","10.0.0.0/18","10.0.0.0/20","192.168.0.0/22"]))
    return PlanConfig(base, gs, random.choice([1.0,1.1,1.25,1.5,2.0]), strategy, gw)

ok = fail = 0
for it in range(20000):
    strategy = random.choice(["vlsm","fixed"]); gw = random.choice(["first","last","none"]); v6 = random.random()<0.2
    cfg = rnd_cfg(strategy, gw, v6)
    base = cfg.base_network; w = base.max_prefixlen
    sizes = []
    for g in cfg.groups:
        r = required_addresses(g, cfg.growth_factor, gw, base.version)
        sizes.append(1 << (w - prefix_for(r, w, g.name)))
    if strategy == "fixed":
        total = len(sizes) * max(sizes)
    else:
        total = sum(sizes)
    feasible = total <= base.num_addresses
    try:
        plan = plan_subnets(cfg)
    except PlanError:
        assert not feasible, (cfg, total); fail += 1; continue
    assert feasible; ok += 1
    nets = [s.network for s in plan.subnets]
    # alignment, inside, disjoint
    for a in nets:
        assert int(a.network_address) % a.num_addresses == 0
        assert a.subnet_of(base)
    for a, b in itertools.combinations(nets, 2):
        assert not a.overlaps(b)
    # contiguity
    S = sum(n.num_addresses for n in nets)
    assert int(nets[0].network_address) == int(base.network_address)
    pos = int(base.network_address)
    for n in nets:
        assert int(n.network_address) == pos; pos += n.num_addresses
    assert pos == int(base.network_address) + S
    # usable = size - overhead
    for s, g in zip(plan.subnets, [next(g for g in cfg.groups if g.name == s.group) for s in plan.subnets]):
        r = required_addresses(g, cfg.growth_factor, gw, base.version)
        overhead = (2 if base.version == 4 else 1) + (gw != "none")
        assert s.usable_hosts == s.network.num_addresses - overhead
        assert s.usable_hosts >= math.ceil(round(g.hosts*cfg.growth_factor, 9)) - 0
        if strategy == "vlsm": assert s.network.num_addresses < 2*r
    # vlsm order
    if strategy == "vlsm":
        ps = [n.prefixlen for n in nets]; assert ps == sorted(ps)
    # free ranges
    F = base.num_addresses - S
    fr = plan.free_ranges
    assert sum(f.num_addresses for f in fr) == F
    assert len(fr) == bin(F).count("1")
    assert [f.num_addresses for f in fr] == sorted(f.num_addresses for f in fr)
    assert sorted(f.num_addresses for f in fr) == [1<<b for b in range(F.bit_length()) if F>>b & 1]
    # packability extend: random new items sum <= F always fit (check via buddy)
    assert plan.allocated_addresses == S
print("plans ok", ok, "infeasible", fail)

# packability theorem, brute force in universe 2^6
def blocks_of(w):
    for k in range(w+1):
        for i in range(2**(w-k)):
            yield (i<<k, k)
W = 5
U = 1<<W
def fits(free_mask, items):
    items = sorted(items, reverse=True)
    def rec(idx, mask):
        if idx == len(items): return True
        k = items[idx]; sz = 1<<k
        for a in range(0, U, sz):
            m = ((1<<sz)-1) << a
            if mask & m == m:
                if rec(idx+1, mask & ~m): return True
        return False
    return rec(0, free_mask)
def cond(free_mask, items):
    # maximal free aligned blocks
    maxb = []
    for k in range(W, -1, -1):
        sz=1<<k
        for a in range(0,U,sz):
            m=((1<<sz)-1)<<a
            if free_mask & m == m and not any((b[0] <= a and a+sz <= b[0]+(1<<b[1])) for b in maxb):
                maxb.append((a,k))
    for j in range(W+1):
        if sum(1<<k for k in items if k>=j) > sum(1<<k for a,k in maxb if k>=j): return False
    return True
cnt=0
for _ in range(4000):
    free = 0
    for a in range(U):
        if random.random()<0.6: free |= 1<<a
    # make free a union of aligned blocks: randomly occupy aligned blocks instead
    occ = 0
    for _ in range(random.randint(0,6)):
        k = random.randint(0,3); a = random.randrange(0,U,1<<k); occ |= ((1<<(1<<k))-1)<<a
    free = ((1<<U)-1) & ~occ
    items = [random.randint(0,4) for _ in range(random.randint(1,6))]
    assert fits(free, items) == cond(free, items), (bin(free), items)
    cnt+=1
print("packability theorem ok", cnt)

# float claim
bad = 0
for _ in range(300000):
    h = random.randint(1, 2_000_000)
    gam = Fraction(random.randint(100, 400), 100)
    exact = math.ceil(h*gam)
    got = math.ceil(round(h*float(gam), 9))
    if exact != got: bad += 1
print("float mismatches (h<=2e6, 2 decimals):", bad)
bad=0
for h in range(1, 3000):
  for c in range(100, 301):
    gam = Fraction(c,100)
    if math.ceil(h*gam) != math.ceil(round(h*float(gam),9)): bad+=1
print("exhaustive small mismatches", bad)
print("naive ceil errors:", sum(1 for h in range(1,3000) for c in range(100,301) if math.ceil(h*c/100) != math.ceil(Fraction(h*c,100))))
