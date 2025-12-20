"use client";

import dynamic from "next/dynamic";

const SignalMapCanvas = dynamic(() => import("./SignalMapCanvas"), {
  ssr: false,
  loading: () => (
    <div
      style={{
        width: "100vw",
        height: "100vh",
        display: "grid",
        placeItems: "center",
        background: "#050610",
        color: "rgba(230,236,255,0.75)",
        fontFamily: "ui-sans-serif, system-ui",
      }}
    >
      Loading signal map…
    </div>
  ),
});

export default function SignalMapClient(props: any) {
  return <SignalMapCanvas {...props} />;
}
