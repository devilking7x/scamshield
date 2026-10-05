// Server-side OCR using tesseract.js (Node).
// Why server-side: client-side Tesseract.js was unreliable in the browser
// (CDN worker downloads, service-worker interference, slow on mobile).
// Here we keep ONE warm worker process-wide and reuse it for every request.

import { createWorker } from 'tesseract.js';
import type { Worker } from 'tesseract.js';

let workerPromise: Promise<Worker> | null = null;

function getWorker(): Promise<Worker> {
  if (!workerPromise) {
    workerPromise = (async () => {
      // 'eng' only by default — fast (~15MB traineddata, cached by tesseract.js).
      const worker = await createWorker('eng', 1);
      return worker;
    })().catch((e) => {
      workerPromise = null; // allow retry on next request
      throw e;
    });
  }
  return workerPromise;
}

/** Extract text from an image buffer. Returns trimmed plain text. */
export async function ocrImage(buf: Buffer): Promise<string> {
  const worker = await getWorker();
  const { data } = await worker.recognize(buf);
  return (data.text ?? '').trim();
}
