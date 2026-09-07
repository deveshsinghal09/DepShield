import Link from "next/link";
import { ArrowRight } from "lucide-react";
import type { Scan } from "@/lib/types";
import styles from "./landing-hero.module.css";
import { HumanScan } from "./human-scan";
import { HomeEvidence } from "./home-evidence";

export function LandingHero({ latestScan }: { latestScan?: Scan | null }) {
  const sequence = latestScan?.id.slice(0, 8).toUpperCase() ?? "READY000";

  return (
    <div data-ui="home-console"><section className={styles.hero} data-ui="landing-hero" aria-labelledby="landing-title">
      <div className={styles.frame}>
        <span className={styles.index} aria-hidden="true">
          /01
        </span>

        <div className={styles.scanVisual}><HumanScan /></div>

        <div className={styles.content}>
          <h1 id="landing-title" className={styles.title}>
            <span>Dependency risk</span>
            <span>isn&apos;t optional.</span>
            <span>It&apos;s systematic.</span>
          </h1>

          <span className={styles.rule} aria-hidden="true" />

          <p className={styles.description}>
            DepShield AI continuously maps, analyzes, and correlates
            <br className={styles.desktopBreak} />{" "}
            your software supply chain to expose risk before
            <br className={styles.desktopBreak} />{" "}
            attackers do.
          </p>

          <div className={styles.actions}>
            <Link href="/scan" className={`${styles.button} ${styles.primaryButton} scan-cta`} data-ui="scan-button">
              <span>SCAN PROJECT</span>
              <ArrowRight aria-hidden="true" size={15} strokeWidth={1.8} />
            </Link>
            <Link href="https://github.com/deveshsinghal09/DepShield#readme" className={`${styles.button} ${styles.secondaryButton}`}>
              <span>VIEW DOCUMENTATION</span>
              <ArrowRight aria-hidden="true" size={15} strokeWidth={1.5} />
            </Link>
          </div>
        </div>

        <div className={styles.telemetry} aria-label="Current DepShield system telemetry">
          <span>DEPSHIELD / DEPENDENCY INTELLIGENCE</span>
          <span>SCAN: {sequence}</span>
        </div>
      </div>
    </section><HomeEvidence scan={latestScan ?? null} /></div>
  );
}
