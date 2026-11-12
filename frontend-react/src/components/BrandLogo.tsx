type BrandLogoProps = {
  compact?: boolean;
  className?: string;
};

export function BrandLogo({ compact = false, className = "" }: BrandLogoProps) {
  return (
    <div className={`ddh-brand ${compact ? "ddh-brand-compact" : ""} ${className}`.trim()} aria-label="Digital Defense Hub">
      <img className="ddh-exact-heart" src={compact ? "/branding/ddh-heart-mark.png" : "/branding/ddh-heart-clean.png?v=1"} alt="" aria-hidden="true" />
      {!compact && <span className="ddh-exact-lockup">
        <img className="ddh-exact-wordmark" src="/branding/ddh-wordmark-exact.png?v=5" alt="Digital Defense Hub" />
        <img className="ddh-exact-tagline" src="/branding/ddh-tagline-clean.png?v=1" alt="Secure, Detect, Defend" />
      </span>}
    </div>
  );
}
