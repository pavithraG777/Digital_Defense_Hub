import { useEffect, useRef } from "react";

const networkNodes = [[.105,.31],[.16,.39],[.225,.29],[.29,.51],[.365,.36],[.445,.29],[.515,.41],[.585,.33],[.655,.47],[.72,.27],[.785,.39],[.86,.31],[.91,.5],[.64,.61],[.43,.59],[.205,.62]] as const;
const routes = [[0,4],[1,7],[2,9],[3,10],[4,11],[5,12],[6,13],[7,14],[8,15],[0,10],[2,12],[5,15]] as const;

export function DashboardLiveBackground() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = canvasRef.current;
    const context = canvas?.getContext("2d");
    if (!canvas || !context) return;
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let animationFrame = 0;
    let frame = 0;
    const resize = () => {
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.round(canvas.clientWidth * ratio);
      canvas.height = Math.round(canvas.clientHeight * ratio);
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
    };
    const draw = () => {
      const width = canvas.clientWidth;
      const height = canvas.clientHeight;
      const activeHeight = Math.min(height, 760);
      const time = frame * .012;
      context.clearRect(0, 0, width, height);
      routes.forEach(([fromIndex, toIndex], routeIndex) => {
        const [fromX, fromY] = networkNodes[fromIndex];
        const [toX, toY] = networkNodes[toIndex];
        const startX = fromX * width, startY = fromY * activeHeight;
        const endX = toX * width, endY = toY * activeHeight;
        const controlX = (startX + endX) / 2;
        const controlY = Math.min(startY, endY) - 55 - Math.abs(endX - startX) * .1;
        context.beginPath(); context.moveTo(startX, startY); context.quadraticCurveTo(controlX, controlY, endX, endY);
        context.strokeStyle = "rgba(43,174,255,.20)"; context.lineWidth = .85; context.stroke();
        const progress = (time * (.12 + (routeIndex % 4) * .018) + routeIndex * .081) % 1;
        const inverse = 1 - progress;
        const packetX = inverse * inverse * startX + 2 * inverse * progress * controlX + progress * progress * endX;
        const packetY = inverse * inverse * startY + 2 * inverse * progress * controlY + progress * progress * endY;
        const glow = context.createRadialGradient(packetX, packetY, 0, packetX, packetY, 10);
        glow.addColorStop(0, "rgba(162,235,255,.98)"); glow.addColorStop(.25, "rgba(47,187,255,.72)"); glow.addColorStop(1, "rgba(24,139,255,0)");
        context.fillStyle = glow; context.beginPath(); context.arc(packetX, packetY, 10, 0, Math.PI * 2); context.fill();
      });
      networkNodes.forEach(([x, y], index) => {
        const nodeX = x * width, nodeY = y * activeHeight;
        const pulse = (Math.sin(time * 2.2 + index * .72) + 1) / 2;
        context.strokeStyle = `rgba(55,191,255,${.16 + pulse * .34})`; context.lineWidth = 1;
        context.beginPath(); context.arc(nodeX, nodeY, 4 + pulse * 9, 0, Math.PI * 2); context.stroke();
        context.fillStyle = `rgba(120,225,255,${.55 + pulse * .4})`;
        context.beginPath(); context.arc(nodeX, nodeY, 1.5 + pulse * 1.2, 0, Math.PI * 2); context.fill();
      });
      frame += 1;
      if (!reducedMotion) animationFrame = requestAnimationFrame(draw);
    };
    resize(); draw(); window.addEventListener("resize", resize);
    return () => { window.removeEventListener("resize", resize); cancelAnimationFrame(animationFrame); };
  }, []);
  return <canvas ref={canvasRef} className="dashboard-live-background" aria-label="Animated global security network" />;
}
