type BrandLogoProps = {
  compact?: boolean;
  className?: string;
};

export function BrandLogo({ compact = false, className = "" }: BrandLogoProps) {
  const asset = (name: string) => `${import.meta.env.BASE_URL}branding/${name}`;

  return (
    <div className={`ddh-brand ${compact ? "ddh-brand-compact" : ""} ${className}`.trim()} aria-label="Digital Defense Hub">
      <img className="ddh-exact-heart" src={asset(compact ? "ddh-heart-mark.png" : "ddh-heart-clean.png?v=1")} alt="" aria-hidden="true" />
      {!compact && <span className="ddh-exact-lockup">
        <img className="ddh-exact-wordmark" src={asset("ddh-wordmark-exact.png?v=5")} alt="Digital Defense Hub" />
        <img className="ddh-exact-tagline" src={asset("ddh-tagline-clean.png?v=1")} alt="Secure, Detect, Defend" />
      </span>}
    </div>
  );
}
