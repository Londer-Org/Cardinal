# Running Cardinal on Kubernetes

A second way to run the same stack as `examples/compose.yml`, on Docker
Desktop's Kubernetes. It is not a replacement — `make e2e-up` is what the
end-to-end suite drives and it stays the fast path.

This exists because compose cannot express the thing worth rehearsing. In
compose every container shares one network, so "the application cannot read
Cardinal's database" is true only because nothing tries. Here it is a
NetworkPolicy, and `make k8s-verify-sabotage` deletes it to prove the check
would notice.

## Three namespaces, two estates

```
docker-desktop
├── traefik      the shared edge: TLS, and where forwardAuth runs
├── cardinal     the identity platform, and the only place its database exists
│   ├── postgres      StatefulSet + PVC
│   ├── cardinal      the server
│   └── migrate       a Job, run once
└── example      applications that consume it, with no privileged access
    ├── protected-app   behind forwardAuth; contains no Cardinal code
    └── oidc-client     an OpenID Connect relying party
```

| URL | What it is |
|---|---|
| `https://id.cardinal.test` | The identity platform |
| `https://app.cardinal.test` | An application behind forwardAuth |
| `https://client.cardinal.test` | An OpenID Connect relying party |
| `https://open.cardinal.test` | The same application with no auth, for contrast |

## Getting it up

Kubernetes has to be enabled in Docker Desktop first — Settings → Kubernetes →
Enable Kubernetes. Then:

```sh
make hosts          # says what to add to /etc/hosts
make k8s-up         # certificates, manifests, images, seeding
make k8s-verify     # prove it works
```

`make k8s-up` is idempotent and re-runnable. `make k8s-down` removes all three
namespaces, volumes included.

This can run at the same time as `make e2e-up`: the hostnames are the same and
both resolve to 127.0.0.1, but the compose stack listens on 8443 and this one on
443, so the port tells them apart.

### Every target pins the cluster

`--context docker-desktop`, everywhere, and `up.sh` refuses to run unless the
context's only node is `desktop-control-plane`. That is not ceremony: a
kubeconfig on a work machine holds real clusters too, and `kubectl apply -f k8s/`
with the wrong context selected is one keystroke from a bad afternoon.

## Four things that are different from compose, and why

**Images have to be loaded.** Docker Desktop's Kubernetes does not share
Docker's image store — a pod referring to an image you just built fails with
`ErrImageNeverPull`. Its node is a kind container running containerd, so
`load-images.sh` streams a `docker save` archive into it, which is what `kind
load docker-image` does.

Cardinal itself is deliberately not loaded that way: it comes from Docker Hub as
the published release, because pulling the real artefact from a registry is what
a deployment does. To run local changes instead:

```sh
docker build -t cardinal:dev .
docker save cardinal:dev | docker exec -i desktop-control-plane ctr -n k8s.io images import -
kubectl --context docker-desktop -n cardinal set image deploy/cardinal cardinal=cardinal:dev
kubectl --context docker-desktop -n cardinal patch deploy/cardinal --type=json \
  -p='[{"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"Never"}]'
```

**DNS has to be taught.** compose gave Traefik network aliases so a container
resolving `id.cardinal.test` reached the proxy. Here CoreDNS rewrites the whole
`*.cardinal.test` zone to the Traefik service. This is not a convenience: an
OIDC issuer must be one identifier everywhere, because the `iss` claim in every
token is compared literally against what the client discovered. Giving the pod a
separate internal URL is how "issuer mismatch" reaches production — so
`verify.sh` checks discovery from *inside* a pod, which is the half a host-side
check cannot see.

**The configuration is a Secret, not a ConfigMap.** Only four settings can come
from the environment; the three encryption keys can only be written in the file.
A file containing key material is secret material whatever else is in it.

**The policy set is mounted, not copied.** `kubectl cp` shells out to `tar`
inside the container, and Cardinal's image is distroless. It arrives as a
ConfigMap instead.

## What the checks assert

`make k8s-verify` runs nine. The interesting ones:

- **`app.cardinal.test` returns 401 and `open.cardinal.test/` returns 500.**
  Both are the point. 401 is Cardinal declining and Traefik returning its answer
  instead of the application's. 500 is the same application, reached without the
  middleware, refusing to render a page with blank fields — it says so rather
  than pretending. The contrast is what proves forwardAuth is doing the work.
- **Discovery reports the same issuer from the host and from inside a pod.**
- **A pod in `example` cannot reach the database, or Cardinal directly.**

That last one passes by failing to connect, which is how a check that tests
nothing also looks. `make k8s-verify-sabotage` deletes the policies and expects
it to fail — and it does, which is the only reason to believe it when it passes.

## A Linux machine, joined to the cluster

`cardinal-agent` is deliberately not in the cluster. It writes `/etc/sudoers.d`,
serves a varlink socket `nss-systemd` must reach, and has to survive a reboot
before any container runtime starts — it belongs on a machine, not in the
cluster it talks to.

So `make k8s-host` joins one. The machine is a container, but nothing about how
it reaches Cardinal is simulated: it resolves the same hostname a browser does,
verifies the same certificate against the same local CA, enrolls over the
network with a single-use token, and runs the agent that a `.deb` installed.

This is distinct from `make verify-host`, which runs the userdb server
in-process and never speaks to a Cardinal at all. That one checks the host-side
components agree with `nss-systemd` and `sudo`. This one checks they agree with
a *server*: enrollment over the network, an assignment fetched from it, and a
host certificate signed by its SSH authority.

Fourteen checks, and the three accounts are what make them mean anything:

| Account | In the directory | On this machine |
|---|---|---|
| `k8s-user` | login group + admins | resolves, and may `sudo` |
| `k8s-nonroot` | login group only | resolves, and may **not** `sudo` |
| `k8s-outsider` | has a uid, no grant | **does not resolve at all** |

The last row is the headline claim of the design and the whole difference from
an LDAP-bound machine: a host learns the names of people who may log into it and
nobody else, so compromising the least important machine in a fleet does not
yield every name and uid in the company.

The final check stops the agent and asks again. Everything before it is
consistent with the names having been in `/etc/passwd` all along; the identity
disappearing with the agent is what shows the directory was the source. Local
root survives, which the agent is structurally incapable of removing.
