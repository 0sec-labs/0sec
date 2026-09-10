import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const referencePath = resolve(root, "docs/src/content/docs/commands.md");

// These are reviewed corrections to registered help, not generated prose.
const optionDescriptions = new Map([
  ["0sec scan|--require-scope", "Set 0SEC_REQUIRE_SCOPE for scope-aware execution paths. Ordinary live-target scan already refuses missing scope, independently of this flag."],
  ["0sec scan|--dry-run", "For --emit pr only: print proposed git/gh emission commands. The scan itself still executes."],
  ["0sec review|--dry-run", "For --emit pr only: print proposed git/gh emission commands. The source review itself still executes."],
]);

const escapeTable = (value) => String(value ?? "")
  .replaceAll("|", "\\|").replaceAll("\n", " ")
  .replaceAll("<", "&lt;").replaceAll(">", "&gt;");

function commandPath(command) {
  return command.parent ? `${commandPath(command.parent)} ${command.name()}` : command.name();
}

function collect(command) {
  return command.commands.flatMap((child) => [child, ...collect(child)]);
}

function optionTable(command) {
  if (!command.options.length) return "";
  const rows = command.options.map((option) => {
    const description = optionDescriptions.get(`${commandPath(command)}|${option.long}`) ?? option.description;
    const value = option.defaultValue;
    const defaultValue = value === undefined ? "—"
      : `\`${escapeTable(typeof value === "string" ? value : JSON.stringify(value))}\``;
    const choices = option.argChoices ? ` Choices: ${escapeTable(option.argChoices.join(", "))}.` : "";
    return `| \`${option.flags.replaceAll("|", "\\|")}\`${option.mandatory ? " **required**" : ""} | ${defaultValue} | ${escapeTable(description)}${choices} |`;
  });
  return ["| Option | Registered default | Description |", "| --- | --- | --- |", ...rows].join("\n") + "\n";
}

function argumentTable(command) {
  if (!command.registeredArguments.length) return "";
  return ["| Argument | Required | Description |", "| --- | --- | --- |",
    ...command.registeredArguments.map((arg) => `| \`${escapeTable(arg.name())}\` | ${arg.required ? "Yes" : "No"} | ${escapeTable(arg.description)} |`),
  ].join("\n") + "\n";
}

function updateTable(section, heading, replacement, additions) {
  const expression = new RegExp(`^\\| ${heading} \\|[^\\n]*\\n(?:\\|[^\\n]*\\n)+`, "m");
  if (expression.test(section)) return section.replace(expression, () => replacement);
  if (replacement) additions.push(replacement);
  return section;
}

/** Update mechanical contracts only; preserve descriptions, guides, and safety notes. */
export function syncReference(text, program) {
  const commands = collect(program);
  const byHeading = new Map(commands.map((command) => [commandPath(command).replace(/^0sec /, ""), command]));
  const seen = new Set();
  const errors = [];
  // Each heading owns its body only. Human-written nested sections stay untouched.
  const parts = text.split(/(?=^#{2,6} )/m);
  const output = parts.map((part) => {
    const heading = /^#{3,4} ([a-z][\w-]*(?: [a-z][\w-]*)*)\n/.exec(part)?.[1];
    if (!heading) return part;
    const command = byHeading.get(heading);
    if (!command) {
      if (/^```text\n0sec /m.test(part)) errors.push(`Removed or renamed command section: ${heading}`);
      return part;
    }
    if (seen.has(heading)) errors.push(`Duplicate command section: ${heading}`);
    seen.add(heading);
    const args = command.registeredArguments.map((arg) => {
      const name = arg.name() + (arg.variadic ? "..." : "");
      return arg.required ? `<${name}>` : `[${name}]`;
    });
    const usage = [commandPath(command), ...(command.options.length ? ["[options]"] : []), ...args].join(" ");
    if (!/^```text\n0sec [^\n]*\n```/m.test(part)) {
      errors.push(`Missing usage block: ${heading}`);
      return part;
    }
    let section = part.replace(/^```text\n0sec [^\n]*\n```/m, () => `\`\`\`text\n${usage}\n\`\`\``);
    const additions = [];
    section = updateTable(section, "Argument", argumentTable(command), additions);
    section = updateTable(section, "Option", optionTable(command), additions);
    const aliases = command.aliases().length ? `Aliases: ${command.aliases().map((alias) => `\`${alias}\``).join(", ")}.\n` : "";
    const children = command.commands.length ? `Subcommands: ${command.commands.map((child) => {
      const path = commandPath(child).replace(/^0sec /, "");
      return `[${child.name()}](#${path.replaceAll(" ", "-")})`;
    }).join(" · ")}.\n` : "";
    for (const [label, value] of [["Aliases", aliases], ["Subcommands", children]]) {
      const expression = new RegExp(`^${label}: [^\\n]*\\n`, "m");
      if (expression.test(section)) section = section.replace(expression, () => value);
      else if (value) additions.push(value);
    }
    if (additions.length) section = section.trimEnd() + "\n\n" + additions.join("\n") + "\n";
    return section;
  }).join("");
  for (const heading of byHeading.keys()) {
    if (!seen.has(heading)) errors.push(`New command needs a documented section and workflow review: ${heading}`);
  }
  if (errors.length) throw new Error(errors.join("\n"));
  return output.replace(/\*\*\d+ top-level commands\*\*/, `**${program.commands.length} top-level commands**`);
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length > 1 || (args.length && args[0] !== "--write" && args[0] !== "--check")) {
    throw new Error("Usage: node scripts/sync-cli-docs.mjs [--check|--write]");
  }
  const requireCli = createRequire(resolve(root, "packages/cli/package.json"));
  const { Command } = requireCli("commander");
  const registrations = await import("../packages/cli/dist/commands/index.js");
  const program = new Command().name("0sec");
  for (const [name, register] of Object.entries(registrations)) {
    if (/^register.*Command$/.test(name) && typeof register === "function") register(program);
  }
  if (!program.commands.length) throw new Error("CLI registration produced no commands");
  const current = readFileSync(referencePath, "utf8");
  const updated = syncReference(current, program);
  if (updated !== current) {
    if (args[0] !== "--write") throw new Error("CLI reference is stale. Build the CLI, run pnpm docs:sync, review the diff, and commit commands.md.");
    writeFileSync(referencePath, updated);
    console.log("Updated mechanical CLI reference; workflow and safety notes preserved.");
  } else {
    console.log(`CLI reference matches ${collect(program).length} registered commands and subcommands.`);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error.message);
    console.error("This command reads compiled CLI registrations. Run pnpm --filter '0sec-cli...' build first.");
    process.exitCode = 1;
  });
}
