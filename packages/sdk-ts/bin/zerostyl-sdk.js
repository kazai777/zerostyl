#!/usr/bin/env node
import { CliError, runCli } from '../dist/cli.js';

try {
  const output = runCli(process.argv.slice(2));
  if (output !== undefined) {
    process.stdout.write(output);
  }
} catch (err) {
  if (err instanceof CliError) {
    process.stderr.write(`error: ${err.message}\n`);
    process.exit(1);
  }
  throw err;
}
