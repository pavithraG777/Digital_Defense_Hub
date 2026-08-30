import { useEffect, useRef } from "react";

type Node = { x: number; y: number; vx: number; vy: number; phase: number };

export function AuthLiveBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current as HTMLCanvasElement | null;
    if (!canvas) return;
    const context = canvas.getContext("2d") as CanvasRenderingContext2D;
    if (!context) return;
    const canvasElement: HTMLCanvasElement = canvas;
    const drawingContext: CanvasRenderingContext2D = context;

    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let width = 0;
    let height = 0;
    let ratio = 1;
    let frame = 0;
    let animationFrame = 0;
    const pointer = { x: 0, y: 0, active: false };
    let nodes: Node[] = [];

    function resize() {
      width = canvasElement.clientWidth;
      height = canvasElement.clientHeight;
      ratio = Math.min(window.devicePixelRatio || 1, 1.5);
      canvasElement.width = Math.floor(width * ratio);
      canvasElement.height = Math.floor(height * ratio);
      drawingContext.setTransform(ratio, 0, 0, ratio, 0, 0);
      const count = Math.max(28, Math.min(52, Math.floor((width * height) / 26000)));
      nodes = Array.from({ length: count }, (_, index) => ({
        x: ((index * 97) % count) / count * width,
        y: ((index * 53 + 17) % count) / count * height,
        vx: ((index % 5) - 2) * 0.035,
        vy: (((index * 3) % 5) - 2) * 0.026,
        phase: index * 0.61,
      }));
    }

    function draw() {
      context.clearRect(0, 0, width, height);
      const base = context.createLinearGradient(0, 0, width, height);
      base.addColorStop(0, "rgba(2, 9, 21, 0.16)");
      base.addColorStop(0.5, "rgba(4, 19, 38, 0.1)");
      base.addColorStop(1, "rgba(1, 7, 18, 0.34)");
      context.fillStyle = base;
      context.fillRect(0, 0, width, height);

      const glow = context.createRadialGradient(width * 0.25, height * 0.46, 0, width * 0.25, height * 0.46, width * 0.42);
      glow.addColorStop(0, "rgba(0, 111, 196, 0.12)");
      glow.addColorStop(1, "rgba(0, 27, 58, 0)");
      context.fillStyle = glow;
      context.fillRect(0, 0, width, height);

      const biometricPulse = 0.035 + ((Math.sin(frame * 0.024) + 1) / 2) * 0.055;
      const biometric = context.createRadialGradient(width * 0.245, height * 0.49, width * 0.04, width * 0.245, height * 0.49, width * 0.19);
      biometric.addColorStop(0, `rgba(35, 177, 235, ${biometricPulse})`);
      biometric.addColorStop(0.48, `rgba(28, 135, 215, ${biometricPulse * 0.55})`);
      biometric.addColorStop(1, "rgba(10, 74, 150, 0)");
      context.fillStyle = biometric;
      context.fillRect(0, 0, width * 0.52, height);

      const ringCycle = (frame * 0.7) % 120;
      for (let ring = 0; ring < 3; ring += 1) {
        const radius = 82 + ((ringCycle + ring * 40) % 120);
        const alpha = Math.max(0, 0.22 * (1 - ((ringCycle + ring * 40) % 120) / 120));
        context.strokeStyle = `rgba(48, 180, 235, ${alpha})`;
        context.lineWidth = 1.2;
        context.beginPath();
        context.arc(width * 0.245, height * 0.49, radius, 0, Math.PI * 2);
        context.stroke();
      }

      const fingerprintScanY = height * 0.34 + ((frame * 0.65) % (height * 0.3));
      const fingerprintScan = context.createLinearGradient(width * 0.08, 0, width * 0.43, 0);
      fingerprintScan.addColorStop(0, "rgba(47, 190, 239, 0)");
      fingerprintScan.addColorStop(0.5, "rgba(47, 190, 239, 0.48)");
      fingerprintScan.addColorStop(1, "rgba(47, 190, 239, 0)");
      context.strokeStyle = fingerprintScan;
      context.lineWidth = 1.4;
      context.beginPath();
      context.moveTo(width * 0.08, fingerprintScanY);
      context.lineTo(width * 0.43, fingerprintScanY);
      context.stroke();

      if (!reduceMotion) {
        for (const node of nodes) {
          const influenceX = pointer.active ? (pointer.x - width / 2) * 0.00005 : 0;
          const influenceY = pointer.active ? (pointer.y - height / 2) * 0.00004 : 0;
          node.x += node.vx + influenceX;
          node.y += node.vy + influenceY;
          if (node.x < -20) node.x = width + 20;
          if (node.x > width + 20) node.x = -20;
          if (node.y < -20) node.y = height + 20;
          if (node.y > height + 20) node.y = -20;
        }
      }

      for (let first = 0; first < nodes.length; first += 1) {
        const a = nodes[first];
        for (let second = first + 1; second < nodes.length; second += 1) {
          const b = nodes[second];
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const distance = Math.hypot(dx, dy);
          if (distance > 165) continue;
          const opacity = (1 - distance / 165) * 0.3;
          context.strokeStyle = `rgba(31, 145, 215, ${opacity})`;
          context.lineWidth = 0.7;
          context.beginPath();
          context.moveTo(a.x, a.y);
          context.lineTo(b.x, b.y);
          context.stroke();
          if ((first + second) % 13 === 0) {
            const progress = (Math.sin(frame * 0.012 + a.phase + second) + 1) / 2;
            const px = a.x + (b.x - a.x) * progress;
            const py = a.y + (b.y - a.y) * progress;
            context.fillStyle = "rgba(91, 214, 255, 0.9)";
            context.beginPath();
            context.arc(px, py, 2.1, 0, Math.PI * 2);
            context.fill();
          }
        }
        const pulse = 1.15 + Math.sin(frame * 0.018 + a.phase) * 0.65;
        context.fillStyle = `rgba(62, 191, 239, ${0.32 + pulse * 0.1})`;
        context.beginPath();
        context.arc(a.x, a.y, pulse, 0, Math.PI * 2);
        context.fill();
      }

      const scanX = reduceMotion ? width * 0.34 : ((frame * 0.42) % (width * 0.72)) - width * 0.08;
      const scan = context.createLinearGradient(scanX - 55, 0, scanX + 55, 0);
      scan.addColorStop(0, "rgba(28, 166, 225, 0)");
      scan.addColorStop(0.5, "rgba(28, 166, 225, 0.045)");
      scan.addColorStop(1, "rgba(28, 166, 225, 0)");
      context.fillStyle = scan;
      context.fillRect(scanX - 55, 0, 110, height);

      const formShade = context.createLinearGradient(width * 0.48, 0, width, 0);
      formShade.addColorStop(0, "rgba(1, 6, 15, 0.08)");
      formShade.addColorStop(1, "rgba(1, 5, 13, 0.72)");
      context.fillStyle = formShade;
      context.fillRect(width * 0.48, 0, width * 0.52, height);

      frame += 1;
      if (!reduceMotion) animationFrame = window.requestAnimationFrame(draw);
    }

    const move = (event: PointerEvent) => { pointer.x = event.clientX; pointer.y = event.clientY; pointer.active = true; };
    const leave = () => { pointer.active = false; };
    resize();
    draw();
    window.addEventListener("resize", resize);
    window.addEventListener("pointermove", move, { passive: true });
    window.addEventListener("pointerleave", leave);
    return () => {
      window.cancelAnimationFrame(animationFrame);
      window.removeEventListener("resize", resize);
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerleave", leave);
    };
  }, []);

  return <canvas ref={canvasRef} className="auth-live-canvas" aria-hidden="true" />;
}
