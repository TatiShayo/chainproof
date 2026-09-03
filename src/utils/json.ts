/**
 * Safe JSON parser with support for UTF-8/UTF-16 encodings, BOM stripping,
 * and resilient error handling.
 */
export function safeJsonParse<T = any>(input: string | Buffer): { success: boolean; data?: T; error?: string } {
  try {
    let text: string;

    if (Buffer.isBuffer(input)) {
      // Check for UTF-16 LE BOM (0xFF, 0xFE)
      if (input.length >= 2 && input[0] === 0xff && input[1] === 0xfe) {
        text = input.subarray(2).toString('utf16le');
      }
      // Check for UTF-16 BE BOM (0xFE, 0xFF)
      else if (input.length >= 2 && input[0] === 0xfe && input[1] === 0xff) {
        // Swap bytes from Big-Endian to Little-Endian for Node.js utf16le decoding
        const swapped = Buffer.alloc(input.length - 2);
        for (let i = 2; i < input.length - 1; i += 2) {
          swapped[i - 2] = input[i + 1];
          swapped[i - 1] = input[i];
        }
        text = swapped.toString('utf16le');
      }
      // Check for UTF-8 BOM (0xEF, 0xBB, 0xBF)
      else if (input.length >= 3 && input[0] === 0xef && input[1] === 0xbb && input[2] === 0xbf) {
        text = input.subarray(3).toString('utf8');
      }
      // Check if buffer is UTF-16 LE without BOM (e.g. contains 0x00 every 2nd byte)
      else if (input.length >= 4 && input[1] === 0x00 && input[3] === 0x00) {
        text = input.toString('utf16le');
      } else {
        text = input.toString('utf8');
      }
    } else if (typeof input === 'string') {
      text = input;
      // Strip UTF-8 BOM if present
      if (text.charCodeAt(0) === 0xfeff) {
        text = text.slice(1);
      }
    } else if (typeof input === 'object' && input !== null) {
      return { success: true, data: input as T };
    } else {
      return { success: false, error: 'Input is not a string, buffer, or object' };
    }

    const trimmed = text.trim();
    if (!trimmed) {
      return { success: false, error: 'Input is empty' };
    }

    try {
      const parsed = JSON.parse(trimmed);
      return { success: true, data: parsed };
    } catch (parseErr: any) {
      // Attempt light repair: strip trailing commas before closing braces/brackets
      try {
        const cleaned = trimmed
          .replace(/,\s*([}\]])/g, '$1')
          .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '');
        const parsedCleaned = JSON.parse(cleaned);
        return { success: true, data: parsedCleaned };
      } catch {
        return { success: false, error: `JSON Parse Error: ${parseErr.message}` };
      }
    }
  } catch (err: any) {
    return { success: false, error: `Unexpected error during JSON parse: ${err.message}` };
  }
}

/**
 * Safe JSON stringify helper with circular reference prevention.
 */
export function safeJsonStringify(obj: unknown, space: number = 2): string {
  const seen = new WeakSet();
  return JSON.stringify(
    obj,
    (key, value) => {
      if (typeof value === 'object' && value !== null) {
        if (seen.has(value)) {
          return '[Circular]';
        }
        seen.add(value);
      }
      return value;
    },
    space
  );
}
