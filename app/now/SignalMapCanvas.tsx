"use client";

import React, { useMemo, useRef, useState, useCallback } from "react";
import Link from "next/link";
import { Canvas, useFrame } from "@react-three/fiber";
import * as THREE from "three";
import { nexusSearchClient, type NexusSearchResult } from "@/lib/nexus-client";

type NodeId = string;

export type SignalNode = {
  id: NodeId;
  title: string;
  url?: string;
  source?: string;
  published?: string;
  severity?: string;
  summary_impact?: string;
  origin: "postgrest" | "nexus";
  x: number;
  y: number;
  r: number;
  color: string;
};

export type Edge = {
  a: NodeId;
  b: NodeId;
  w: number; // 0..1
};

const severityColor = (sev?: string) => {
  switch ((sev ?? "").toUpperCase()) {
    case "CRITICAL":
      return "#ff3b6b";
    case "HIGH":
      return "#ff7a3b";
    case "MEDIUM":
      return "#ffd43b";
    case "LOW":
      return "#4dd4ff";
    default:
      return "#b7b7ff";
  }
};

function phyllotaxis(i: number, scale = 6) {
  const golden = Math.PI * (3 - Math.sqrt(5));
  const r = scale * Math.sqrt(i);
  const theta = i * golden;
  return { x: r * Math.cos(theta), y: r * Math.sin(theta) };
}

function SdfStars({
  nodes,
  onPick,
}: {
  nodes: SignalNode[];
  onPick: (id: string) => void;
}) {
  const geom = useMemo(() => new THREE.PlaneGeometry(1, 1), []);

  const mat = useMemo(() => {
    return new THREE.ShaderMaterial({
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      uniforms: {
        uTime: { value: 0 },
        uColor: { value: new THREE.Color("#ffffff") },
        uSeed: { value: 0 },
      },
      vertexShader: `
        varying vec2 vUv;
        void main() {
          vUv = uv;
          vec4 mv = modelViewMatrix * vec4(position, 1.0);
          gl_Position = projectionMatrix * mv;
        }
      `,
      fragmentShader: `
        precision highp float;
        varying vec2 vUv;
        uniform float uTime;
        uniform vec3 uColor;
        uniform float uSeed;

        void main() {
          vec2 p = vUv * 2.0 - 1.0;
          float d = length(p);

          float core = smoothstep(0.35, 0.0, d);
          float halo = smoothstep(1.0, 0.0, d);

          float tw = 0.65 + 0.35*sin(uTime*1.2 + uSeed*12.3);
          float a = (core*0.9 + halo*0.35) * tw;

          vec3 col = uColor;
          col *= 0.85 + 0.15*cos(6.2831*(d*0.75 + uSeed*0.11) + vec3(0.0,2.0,4.0));

          a *= smoothstep(1.0, 0.8, d);
          gl_FragColor = vec4(col, a);
        }
      `,
    });
  }, []);

  useFrame((_, dt) => {
    (mat.uniforms.uTime.value as number) += dt;
  });

  return (
    <group>
      {nodes.map((n, idx) => {
        const c = new THREE.Color(n.color);
        return (
          <mesh
            key={n.id}
            geometry={geom}
            material={mat}
            position={[n.x, n.y, 0]}
            scale={[n.r * 2.2, n.r * 2.2, 1]}
            onPointerDown={(e) => {
              e.stopPropagation();
              onPick(n.id);
            }}
            onPointerOver={() => {
              mat.uniforms.uColor.value = c;
              mat.uniforms.uSeed.value = idx * 0.17;
            }}
          />
        );
      })}
    </group>
  );
}

function Edges({ nodesById, edges }: { nodesById: Map<string, SignalNode>; edges: Edge[] }) {
  const positions = useMemo(() => {
    const pts: number[] = [];
    for (const e of edges) {
      const a = nodesById.get(e.a);
      const b = nodesById.get(e.b);
      if (!a || !b) continue;
      pts.push(a.x, a.y, 0, b.x, b.y, 0);
    }
    return new Float32Array(pts);
  }, [nodesById, edges]);

  const geo = useMemo(() => {
    const g = new THREE.BufferGeometry();
    g.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    return g;
  }, [positions]);

  const mat = useMemo(() => {
    return new THREE.LineBasicMaterial({
      color: new THREE.Color("#7aa2ff"),
      transparent: true,
      opacity: 0.12,
      blending: THREE.AdditiveBlending,
    });
  }, []);

  return <lineSegments geometry={geo} material={mat} />;
}

function usePanZoom() {
  const ref = useRef<THREE.Group>(null);
  const state = useRef({
    dragging: false,
    lastX: 0,
    lastY: 0,
    tx: 0,
    ty: 0,
    s: 1,
  });

  const bind = {
    onPointerDown: (e: any) => {
      if (e.button !== 0) return;
      state.current.dragging = true;
      state.current.lastX = e.clientX;
      state.current.lastY = e.clientY;
    },
    onPointerUp: () => {
      state.current.dragging = false;
    },
    onPointerLeave: () => {
      state.current.dragging = false;
    },
    onPointerMove: (e: any) => {
      if (!state.current.dragging) return;
      const dx = e.clientX - state.current.lastX;
      const dy = e.clientY - state.current.lastY;
      state.current.lastX = e.clientX;
      state.current.lastY = e.clientY;
      state.current.tx += dx * 0.02;
      state.current.ty -= dy * 0.02;
      if (ref.current) ref.current.position.set(state.current.tx, state.current.ty, 0);
    },
    onWheel: (e: any) => {
      e.preventDefault?.();
      const delta = Math.sign(e.deltaY);
      const k = delta > 0 ? 0.92 : 1.08;
      state.current.s = Math.max(0.25, Math.min(4, state.current.s * k));
      if (ref.current) ref.current.scale.setScalar(state.current.s);
    },
  };

  return { ref, bind };
}

function Inspector({
  selected,
  onClose,
  onExpand,
  busy,
}: {
  selected: SignalNode | null;
  onClose: () => void;
  onExpand: () => void;
  busy: boolean;
}) {
  if (!selected) return null;

  return (
    <aside
      style={{
        position: "absolute",
        right: 16,
        top: 16,
        width: 380,
        maxWidth: "calc(100vw - 32px)",
        borderRadius: 18,
        border: "1px solid rgba(255,255,255,0.12)",
        background: "rgba(10, 12, 18, 0.72)",
        backdropFilter: "blur(10px)",
        color: "#e8ecff",
        padding: 14,
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <div
          style={{
            width: 10,
            height: 10,
            borderRadius: 999,
            background: selected.color,
            boxShadow: `0 0 18px ${selected.color}`,
          }}
        />
        <div style={{ fontWeight: 800, lineHeight: 1.1, flex: 1 }}>{selected.title}</div>
        <button
          onClick={onClose}
          style={{
            appearance: "none",
            border: "1px solid rgba(255,255,255,0.15)",
            background: "transparent",
            color: "#e8ecff",
            borderRadius: 12,
            padding: "6px 10px",
            cursor: "pointer",
          }}
        >
          Close
        </button>
      </div>

      <div style={{ marginTop: 10, fontSize: 12, opacity: 0.8 }}>
        {selected.source ? <span>{selected.source}</span> : null}
        {selected.published ? <span> · {selected.published}</span> : null}
        {selected.severity ? <span> · {selected.severity}</span> : null}
      </div>

      {selected.summary_impact ? (
        <p style={{ marginTop: 10, fontSize: 13, lineHeight: 1.45, opacity: 0.92 }}>
          {selected.summary_impact}
        </p>
      ) : null}

      <div style={{ display: "flex", gap: 10, marginTop: 12 }}>
        <button
          onClick={onExpand}
          disabled={busy}
          style={{
            flex: 1,
            appearance: "none",
            border: "1px solid rgba(255,255,255,0.15)",
            background: "rgba(255,255,255,0.06)",
            color: "#e8ecff",
            borderRadius: 14,
            padding: "10px 12px",
            cursor: busy ? "not-allowed" : "pointer",
            fontWeight: 700,
          }}
        >
          {busy ? "Searching…" : "Expand neighborhood"}
        </button>

        {selected.origin === "postgrest" ? (
          <Link
            href={`/item/${selected.id}`}
            style={{
              appearance: "none",
              border: "1px solid rgba(255,255,255,0.15)",
              background: "transparent",
              color: "#e8ecff",
              borderRadius: 14,
              padding: "10px 12px",
              textDecoration: "none",
              fontWeight: 700,
              display: "inline-flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            Read
          </Link>
        ) : null}
      </div>

      {selected.url ? (
        <a
          href={selected.url}
          target="_blank"
          rel="noreferrer"
          style={{
            display: "block",
            marginTop: 10,
            fontSize: 12,
            color: "rgba(180, 200, 255, 0.85)",
            wordBreak: "break-word",
          }}
        >
          {selected.url}
        </a>
      ) : null}
    </aside>
  );
}

export default function SignalMapCanvas({
  initial,
}: {
  initial: {
    id: string;
    title: string;
    source_name?: string;
    published?: string;
    link?: string;
    severity_level?: string;
    severity_rank?: number;
    summary_impact?: string;
  }[];
}) {
  const [nodes, setNodes] = useState<SignalNode[]>(() => {
    return initial.map((it, i) => {
      const p = phyllotaxis(i, 5.5);
      const r = 0.9 + Math.min(2.2, (it.severity_rank ?? 10) / 24);
      return {
        id: it.id,
        title: it.title,
        url: it.link,
        source: it.source_name,
        published: it.published,
        severity: it.severity_level,
        summary_impact: it.summary_impact,
        origin: "postgrest",
        x: p.x,
        y: p.y,
        r,
        color: severityColor(it.severity_level),
      };
    });
  });

  const [edges, setEdges] = useState<Edge[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const nodesById = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);
  const selected = selectedId ? nodesById.get(selectedId) ?? null : null;

  const { ref, bind } = usePanZoom();

  const addNeighbors = useCallback((center: SignalNode, results: NexusSearchResult[]) => {
    setNodes((prev) => {
      const existing = new Map(prev.map((n) => [n.id, n]));

      results.forEach((r, j) => {
        if (existing.has(r.id)) return;
        const angle = (j / Math.max(1, results.length)) * Math.PI * 2;
        const dist = 9 + (1 - (r.score ?? 0)) * 12;
        const x = center.x + Math.cos(angle) * dist;
        const y = center.y + Math.sin(angle) * dist;

        existing.set(r.id, {
          id: r.id,
          title: r.title,
          url: r.url,
          source: r.source,
          published: r.published,
          severity: r.severity,
          summary_impact: r.summary_impact,
          origin: "nexus",
          x,
          y,
          r: 1.05,
          color: severityColor(r.severity),
        });
      });

      return Array.from(existing.values());
    });

    setEdges((prev) => {
      const next = [...prev];
      results.forEach((r) => {
        next.push({ a: center.id, b: r.id, w: r.score ?? 0 });
      });
      return next.slice(-1200);
    });
  }, []);

  const onExpand = useCallback(async () => {
    if (!selected) return;
    setBusy(true);
    try {
      const q = `${selected.title}\n${selected.summary_impact ?? ""}`.trim();
      const resp = await nexusSearchClient(q, 12);
      addNeighbors(selected, resp.results);
    } finally {
      setBusy(false);
    }
  }, [selected, addNeighbors]);

  return (
    <div
      style={{
        position: "relative",
        width: "100vw",
        height: "100vh",
        overflow: "hidden",
        background:
          "radial-gradient(1200px 900px at 30% 20%, rgba(60,80,160,0.22), transparent 60%), radial-gradient(900px 700px at 70% 70%, rgba(180,70,170,0.14), transparent 55%), #050610",
      }}
    >
      <div
        style={{
          position: "absolute",
          left: 18,
          top: 16,
          color: "rgba(230, 236, 255, 0.92)",
          fontFamily: "ui-sans-serif, system-ui",
        }}
      >
        <div style={{ fontSize: 13, letterSpacing: 0.6, opacity: 0.7 }}>
          TIGERBLUE / SIGNAL MAP
        </div>
        <div style={{ marginTop: 4, fontSize: 18, fontWeight: 900 }}>Now</div>
        <div style={{ marginTop: 6, fontSize: 12, opacity: 0.7, maxWidth: 340 }}>
          Drag to pan · Scroll to zoom · Click a star to inspect · Expand to pull semantic neighbors
        </div>
      </div>

      <Canvas
        dpr={[1, 2]}
        orthographic
        camera={{ position: [0, 0, 100], zoom: 10 }}
        onPointerMissed={() => setSelectedId(null)}
        gl={{ antialias: true, alpha: true }}
        style={{ width: "100%", height: "100%" }}
        {...(bind as any)}
      >
        <color attach="background" args={["#050610"]} />
        <ambientLight intensity={0.7} />

        <group ref={ref}>
          <Edges nodesById={nodesById} edges={edges} />
          <SdfStars nodes={nodes} onPick={(id) => setSelectedId(id)} />
        </group>
      </Canvas>

      <Inspector
        selected={selected}
        busy={busy}
        onClose={() => setSelectedId(null)}
        onExpand={onExpand}
      />

      <div
        style={{
          position: "absolute",
          left: 18,
          bottom: 14,
          fontSize: 12,
          color: "rgba(210,220,255,0.6)",
          display: "flex",
          gap: 10,
          alignItems: "center",
        }}
      >
        <span style={{ opacity: 0.7 }}>{nodes.length} nodes</span>
        <span style={{ opacity: 0.4 }}>·</span>
        <Link
          href="/"
          style={{ color: "rgba(210,220,255,0.75)", textDecoration: "none" }}
        >
          Home
        </Link>
        <span style={{ opacity: 0.4 }}>·</span>
        <Link
          href="/timeline"
          style={{ color: "rgba(210,220,255,0.75)", textDecoration: "none" }}
        >
          Timeline
        </Link>
        <span style={{ opacity: 0.4 }}>·</span>
        <Link
          href="/sitrep"
          style={{ color: "rgba(210,220,255,0.75)", textDecoration: "none" }}
        >
          Sitrep
        </Link>
        <span style={{ opacity: 0.4 }}>·</span>
        <Link
          href="/kev"
          style={{ color: "rgba(210,220,255,0.75)", textDecoration: "none" }}
        >
          KEV
        </Link>
        <span style={{ opacity: 0.4 }}>·</span>
        <Link
          href="/epss"
          style={{ color: "rgba(210,220,255,0.75)", textDecoration: "none" }}
        >
          EPSS
        </Link>
      </div>
    </div>
  );
}
