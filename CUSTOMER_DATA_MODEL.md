# Cybersecurity Graph Model

A reference for how vulnerability management platforms like Cogent, Wiz, and BloodHound represent their domain as a graph — what the nodes are, what the edges are, and why each concept earns the role it has.

For the non-customer-specific vulnerability intelligence layer, see [GLOBAL_LAYER_README.md](GLOBAL_LAYER_README.md).

## Why a graph

Vulnerability management isn't "find CVEs." Anyone with a scanner does that. The actual question security teams ask is closer to:

> Which of my **assets**, owned by which **teams**, are running which **software** with which **vulnerabilities**, exploitable from which **networks** by which **identities**?

Each bolded noun is a node type. Each "with / by / from" is an edge. The schema follows the questions you want to answer.

Graphs scale for this because relationships are first-class. Traversing an edge costs O(degree of the node), independent of the rest of the dataset — no JOIN tax per hop. Variable-length queries ("anything within 4 hops") are graph-native and painful in SQL.

## Node types

### Asset
Anything you own that could be a target.
- **Properties:** `{hostname, ip, cloud_provider, instance_id, criticality, environment}`
- **Examples:** EC2 instance, laptop, container, database, repo.

### Identity
A "who" — anything that can authenticate and act.
- **Properties:** `{email, type, mfa_enabled, last_active}`
- **Examples:** user, service account, OAuth app, machine identity.

### Vulnerability
A known weakness, usually a CVE. Exists independent of any one asset.
- **Properties:** `{cve_id, cvss, kev_status, epss_score, published_date}`

### Package
The piece of software that *has* the vulnerability.
- **Properties:** `{name, ecosystem}` — e.g. `{name: "log4j", ecosystem: "maven"}`

### PackageVersion
A specific version of a package. Vulnerabilities attach here, not to Package.
- **Properties:** `{version}` — e.g. `2.14.1`

### Network
The connectivity layer.
- **Properties:** `{cidr, type, is_public}`
- **Examples:** subnet, VPC, the public internet.

### Owner
Who's responsible for fixing things on an asset. Customer-specific data.
- **Properties:** `{name, slack_channel, jira_project}`

### Finding
The customer-specific *instance* of a vulnerability on an asset. The thing with a lifecycle.
- **Properties:** `{state, severity_in_context, owner, deadline, ticket_url, first_seen, last_seen}`
- **States:** `open → triaged → fix_proposed → deployed → verified → closed`

## Edge types

Edges are typed and can carry properties of their own.

### From Asset
- `Asset --RUNS--> PackageVersion` — software running on this asset
- `Asset --IS_IN--> Subnet` — network membership
- `Asset --REACHABLE_FROM--> Network` (props: `{ports, protocols}`) — connectivity
- `Asset --OWNED_BY--> Owner` — responsibility

### From Identity
- `Identity --HAS_ACCESS_TO--> Asset` (props: `{role, permissions}`)
- `Identity --MEMBER_OF--> Group`
- `Identity --ASSUMES--> Role` and `Role --GRANTS_ACCESS_TO--> Asset`
- `Identity --GRANTED_OAUTH--> OAuthApp` (props: `{scopes, granted_at}`) — third-party OAuth grants

### Vulnerability / Package
- `Vulnerability --AFFECTS--> PackageVersion`
- `PackageVersion --IS_VERSION_OF--> Package`
- `PackageVersion --FIXES--> Vulnerability` — newer versions that resolve a CVE

### From Finding
- `Finding --DETECTS--> Vulnerability`
- `Finding --ON--> Asset`
- `Finding --REPORTED_BY--> Scanner`

### Network topology
- `Subnet --PEERED_WITH--> Subnet`
- `Subnet --PART_OF--> VPC`

## Design rule: node vs. edge

A concept earns node status when it satisfies all three:

1. **Stable identity over time** — it has an ID that survives across observations and accumulates state.
2. **Many relationships** — participates in lots of connections to other things.
3. **You query starting from it** — typical questions begin "for this *<thing>*, show me…".

Things that are *only* connections without their own state become edges.

The interesting case is **Finding**. It could be modeled as an edge between Vulnerability and Asset. Most platforms promote it to a node because it has its own lifecycle and properties. When a relationship grows attributes and state, it gets promoted. Same pattern as a SQL junction table becoming a first-class entity once it accumulates its own columns.

## Worked example 1 — vulnerability triage

> "Show me critical open findings on internet-exposed assets owned by the platform team."

```cypher
MATCH (f:Finding {state: 'open', severity: 'critical'})
      -[:ON]->(a:Asset)
      -[:REACHABLE_FROM]->(:Network {is_public: true})
MATCH (a)-[:OWNED_BY]->(:Owner {name: 'platform'})
RETURN f, a
```

The same query in SQL would be a five-table JOIN with poor selectivity. In a graph DB it's a few thousand pointer-follows.

## Worked example 2 — blast radius

> "If this OAuth app is compromised, what's reachable in our environment within 3 hops?"

```cypher
MATCH path = (o:OAuthApp {client_id: '...'})
              <-[:GRANTED_OAUTH]-(:Identity)
              -[:HAS_ACCESS_TO*1..3]->(reachable)
RETURN path
```

That `*1..3` is variable-length traversal — first-class in graphs, awkward in SQL (recursive CTEs, different topology per hop count).

## Populating the graph

The graph is built by connectors that translate source-specific data into the ontology. Each connector knows how to map its source's records into the canonical node and edge types.

| Source | Maps to |
|---|---|
| Tenable host record | `Asset` node |
| Tenable plugin output | `Vulnerability` + `Finding` |
| Wiz issue | `Finding` |
| GitHub CODEOWNERS | `Owner` + `OWNED_BY` edges |
| AWS Config | `Asset` nodes + `IS_IN` edges |
| Okta | `Identity` nodes + `HAS_ACCESS_TO` edges |
| Snyk | `Finding` + `PackageVersion` linkage |

The hard problem at this layer is **entity resolution**. When Wiz, Tenable, and AWS Config all describe "the same" EC2 instance through different identifiers, they have to merge into one `Asset` node — not three. Get this wrong and the rest of the graph is corrupt: blast radius queries return wrong results, ownership routing goes to the wrong team, dedup fails.

## Mental model

Every node type corresponds to a real-world concept that has its own life. Asset has a life (provisioned, runs, decommissioned). Identity has a life. Finding has a life. The edges capture relationships *between* those lives.

Compose them and you get queries like "for any *asset* an *identity* with admin role can reach over the *network*, show me the *findings* still in `open` state with a *vulnerability* in CISA KEV." Six node types, four edge types — and it answers a real security question. That's why the schema looks the way it does.
