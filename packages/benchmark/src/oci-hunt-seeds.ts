/**
 * First curated Docker / OCI image hunt seed list.
 *
 * These are public images with enough application / filesystem surface to
 * make merged-rootfs review meaningful. The goal is not exhaustive coverage;
 * the goal is a repeatable first batch for the new `--ecosystem oci` lane.
 */

export interface OciHuntSeedCategory {
  id: string;
  label: string;
  rationale: string;
  images: string[];
}

export const OCI_HUNT_SEED_CATEGORIES: OciHuntSeedCategory[] = [
  {
    id: "web-app-runtimes",
    label: "Web App Runtimes",
    rationale:
      "Framework and app-runtime images are the most likely to expose " +
      "interesting config, startup, and embedded-app filesystem surfaces.",
    images: [
      "nginx:alpine",
      "httpd:alpine",
      "traefik:v3.1",
      "caddy:2-alpine",
      "node:22-alpine",
      "python:3.12-alpine",
      "php:8.3-apache",
    ],
  },
  {
    id: "data-stores",
    label: "Datastores / Search",
    rationale:
      "Database and search images often embed risky defaults, config files, " +
      "plugins, and bootstrapping scripts worth auditing.",
    images: [
      "postgres:16-alpine",
      "mysql:8.4",
      "redis:7-alpine",
      "mongo:8",
      "elasticsearch:8.15.0",
    ],
  },
  {
    id: "message-brokers",
    label: "Messaging / Queues",
    rationale:
      "Broker images frequently expose complex startup scripts, auth defaults, " +
      "and plugin surfaces.",
    images: [
      "rabbitmq:4-management",
      "nats:2.10-alpine",
      "apache/kafka:3.8.0",
    ],
  },
  {
    id: "developer-platforms",
    label: "Developer / CI Platforms",
    rationale:
      "These images tend to carry larger toolchains and richer embedded " +
      "filesystem surfaces for config and secret-handling review.",
    images: [
      "jenkins/jenkins:lts-jdk21",
      "gitlab/gitlab-ce:17.5.1-ce.0",
      "gitea/gitea:1.22.3",
      "sonarqube:community",
    ],
  },
];

export const OCI_HUNT_SEEDS = Array.from(
  new Set(OCI_HUNT_SEED_CATEGORIES.flatMap((category) => category.images)),
);

export function ociHuntSeedsCsv(): string {
  return OCI_HUNT_SEEDS.join(",");
}
