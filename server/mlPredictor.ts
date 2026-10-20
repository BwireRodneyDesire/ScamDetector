import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";
import path from "node:path";

const predictorPath = path.resolve(process.cwd(), "ml", "predictor.py");
const pythonCommand = process.env.PHISHGUARD_PYTHON ?? "python";
let processInstance: ChildProcessWithoutNullStreams | null = null;
let nextRequestId = 1;
const pending = new Map<
  number,
  { resolve: (value: MlPrediction) => void; reject: (error: Error) => void }
>();

export type MlPrediction = {
  available: boolean;
  model?: string;
  probability?: number;
  error?: string;
};

function stopProcess(error: Error) {
  processInstance = null;
  for (const request of Array.from(pending.values())) request.reject(error);
  pending.clear();
}

function ensureProcess() {
  if (processInstance) return processInstance;
  const child = spawn(pythonCommand, [predictorPath, "--server"], {
    cwd: path.dirname(predictorPath),
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true,
  });
  processInstance = child;
  child.stderr.resume();
  const output = createInterface({ input: child.stdout });
  output.on("line", line => {
    try {
      const result = JSON.parse(line) as MlPrediction & { id?: number };
      if (typeof result.id !== "number") return;
      const request = pending.get(result.id);
      if (!request) return;
      pending.delete(result.id);
      request.resolve(result);
    } catch {
      // Invalid child output is handled by the request timeout.
    }
  });
  child.on("error", error => stopProcess(error));
  child.on("exit", code => {
    if (processInstance === child)
      stopProcess(new Error(`Local ML process exited with code ${code ?? "unknown"}.`));
  });
  return child;
}

export async function predictUrlWithLocalModel(
  url: string
): Promise<MlPrediction> {
  try {
    const child = ensureProcess();
    const id = nextRequestId++;
    const result = await new Promise<MlPrediction>((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error("The local ML model timed out."));
      }, 10_000);
      pending.set(id, {
        resolve: value => {
          clearTimeout(timer);
          resolve(value);
        },
        reject: error => {
          clearTimeout(timer);
          reject(error);
        },
      });
      child.stdin.write(`${JSON.stringify({ id, url })}\n`, error => {
        if (error) {
          clearTimeout(timer);
          pending.delete(id);
          reject(error);
        }
      });
    });
    if (
      result.available !== true ||
      typeof result.probability !== "number" ||
      !Number.isFinite(result.probability)
    )
      return {
        available: false,
        error: result.error ?? "The local model returned an invalid result.",
      };
    return result;
  } catch (error) {
    return {
      available: false,
      error:
        error instanceof Error
          ? error.message
          : "The local model could not be executed.",
    };
  }
}
