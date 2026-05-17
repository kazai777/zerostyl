import { readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { generateBindings } from './codegen/generator.js';
import { parseAbiSchema } from './types.js';

export class CliError extends Error {
  override readonly name = 'CliError';
}

export interface GenerateOptions {
  command: 'generate';
  abi: string;
  out?: string;
}

export function parseCli(argv: readonly string[]): GenerateOptions {
  const [command, ...rest] = argv;
  if (command !== 'generate') {
    throw new CliError(
      `unknown command '${command ?? '<none>'}' — expected 'generate'\n\nusage: zerostyl-sdk generate --abi <path> [--out <path>]`,
    );
  }
  const { values } = parseArgs({
    args: rest as string[],
    options: {
      abi: { type: 'string', short: 'a' },
      out: { type: 'string', short: 'o' },
    },
    strict: true,
  });
  if (!values.abi) {
    throw new CliError('missing required --abi <path>');
  }
  return { command: 'generate', abi: values.abi, out: values.out };
}

export function runCli(argv: readonly string[]): string | undefined {
  const opts = parseCli(argv);
  const abiSource = readFileSync(opts.abi, 'utf8');
  const abi = parseAbiSchema(abiSource);
  const ts = generateBindings(abi);
  if (opts.out !== undefined) {
    writeFileSync(opts.out, ts);
    return undefined;
  }
  return ts;
}
