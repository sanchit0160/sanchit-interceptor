/**
 * Sanchit Interceptor — Advanced Diff Engine
 * Copyright (c) 2026 Sanchit. All rights reserved.
 *
 * Implements Longest Common Subsequence (LCS) diffing:
 * - Line-level alignment with insertion/deletion/modification detection
 * - Inline word-level token diffing for modified lines
 * - Side-by-side aligned diff generation with synchronization gaps
 * - Unified inline diff generation
 * - Similarity score calculation
 */

/**
 * Tokenize string into lines
 */
export function splitLines(text, ignoreWhitespace = false, ignoreCase = false) {
  if (!text) return [];
  const raw = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
  return raw.map((line, idx) => {
    let key = line;
    if (ignoreWhitespace) key = key.trim().replace(/\s+/g, ' ');
    if (ignoreCase) key = key.toLowerCase();
    return {
      num: idx + 1,
      text: line,
      key: key,
    };
  });
}

/**
 * Tokenize string into words & punctuation
 */
export function tokenizeWords(text) {
  if (!text) return [];
  return text.match(/[\w]+|[^\w\s]+|\s+/g) || [text];
}

/**
 * Compute Longest Common Subsequence (LCS) matrix
 */
function computeLcs(aList, bList, keyProp = 'key') {
  const m = aList.length;
  const n = bList.length;
  // Initialize (m+1) x (n+1) table
  const dp = Array.from({ length: m + 1 }, () => new Uint32Array(n + 1));

  for (let i = 1; i <= m; i++) {
    const valA = keyProp ? aList[i - 1][keyProp] : aList[i - 1];
    for (let j = 1; j <= n; j++) {
      const valB = keyProp ? bList[j - 1][keyProp] : bList[j - 1];
      if (valA === valB) {
        dp[i][j] = dp[i - 1][j - 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }

  return dp;
}

/**
 * Backtrack LCS to produce diff edit script
 */
function backtrackLcs(dp, aList, bList, keyProp = 'key') {
  let i = aList.length;
  let j = bList.length;
  const script = [];

  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && (keyProp ? aList[i - 1][keyProp] : aList[i - 1]) === (keyProp ? bList[j - 1][keyProp] : bList[j - 1])) {
      script.push({ type: 'equal', itemA: aList[i - 1], itemB: bList[j - 1] });
      i--;
      j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      script.push({ type: 'insert', itemB: bList[j - 1] });
      j--;
    } else if (i > 0 && (j === 0 || dp[i][j - 1] < dp[i - 1][j])) {
      script.push({ type: 'delete', itemA: aList[i - 1] });
      i--;
    }
  }

  return script.reverse();
}

/**
 * Diff two lines at word level
 */
export function diffWords(lineA, lineB) {
  const wordsA = tokenizeWords(lineA);
  const wordsB = tokenizeWords(lineB);

  const dp = computeLcs(wordsA, wordsB, null);
  let i = wordsA.length;
  let j = wordsB.length;
  const diffA = [];
  const diffB = [];

  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && wordsA[i - 1] === wordsB[j - 1]) {
      diffA.push({ type: 'equal', text: wordsA[i - 1] });
      diffB.push({ type: 'equal', text: wordsB[j - 1] });
      i--;
      j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      diffB.push({ type: 'insert', text: wordsB[j - 1] });
      j--;
    } else if (i > 0 && (j === 0 || dp[i][j - 1] < dp[i - 1][j])) {
      diffA.push({ type: 'delete', text: wordsA[i - 1] });
      i--;
    }
  }

  return {
    wordsA: diffA.reverse(),
    wordsB: diffB.reverse(),
  };
}

/**
 * Convert string or buffer to standard 16-byte hex dump representation
 */
export function formatHexDumpLines(text) {
  const bytes = new TextEncoder().encode(text || '');
  if (!bytes.length) return '';
  const lines = [];
  const chunk = 16;
  for (let i = 0; i < bytes.length; i += chunk) {
    const slice = bytes.subarray(i, i + chunk);
    const offset = i.toString(16).padStart(8, '0');
    const hexParts = [];
    let asciiPart = '';
    for (let j = 0; j < chunk; j++) {
      if (j < slice.length) {
        const b = slice[j];
        hexParts.push(b.toString(16).padStart(2, '0'));
        asciiPart += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
      } else {
        hexParts.push('  ');
      }
    }
    const hexFormatted = hexParts.slice(0, 8).join(' ') + '  ' + hexParts.slice(8).join(' ');
    lines.push(`${offset}  ${hexFormatted}  |${asciiPart}|`);
  }
  return lines.join('\n');
}

/**
 * Main Diff function: computes side-by-side aligned diff and statistics
 */
export function computeDiff(textA, textB, options = {}) {
  const {
    mode = 'lines', // 'lines' | 'words' | 'bytes'
    ignoreWhitespace = false,
    ignoreCase = false,
  } = options;

  let effTextA = textA || '';
  let effTextB = textB || '';
  let effMode = mode;
  if (mode === 'bytes') {
    effTextA = formatHexDumpLines(textA);
    effTextB = formatHexDumpLines(textB);
    effMode = 'words';
  }

  const linesA = splitLines(effTextA, ignoreWhitespace, ignoreCase);
  const linesB = splitLines(effTextB, ignoreWhitespace, ignoreCase);

  const dp = computeLcs(linesA, linesB, 'key');
  const rawScript = backtrackLcs(dp, linesA, linesB, 'key');

  const rows = [];
  let additions = 0;
  let deletions = 0;
  let modifications = 0;
  let matches = 0;

  let k = 0;
  while (k < rawScript.length) {
    const item = rawScript[k];

    if (item.type === 'equal') {
      rows.push({
        type: 'equal',
        leftNum: item.itemA.num,
        leftText: item.itemA.text,
        rightNum: item.itemB.num,
        rightText: item.itemB.text,
      });
      matches++;
      k++;
    } else if (
      item.type === 'delete' &&
      k + 1 < rawScript.length &&
      rawScript[k + 1].type === 'insert'
    ) {
      // Paired modification (delete + insert on same line position)
      const nextItem = rawScript[k + 1];
      let wordDiff = null;

      if (mode === 'words') {
        wordDiff = diffWords(item.itemA.text, nextItem.itemB.text);
      }

      rows.push({
        type: 'modify',
        leftNum: item.itemA.num,
        leftText: item.itemA.text,
        rightNum: nextItem.itemB.num,
        rightText: nextItem.itemB.text,
        wordDiffA: wordDiff ? wordDiff.wordsA : null,
        wordDiffB: wordDiff ? wordDiff.wordsB : null,
      });
      modifications++;
      k += 2;
    } else if (item.type === 'delete') {
      rows.push({
        type: 'delete',
        leftNum: item.itemA.num,
        leftText: item.itemA.text,
        rightNum: null,
        rightText: '',
      });
      deletions++;
      k++;
    } else if (item.type === 'insert') {
      rows.push({
        type: 'insert',
        leftNum: null,
        leftText: '',
        rightNum: item.itemB.num,
        rightText: item.itemB.text,
      });
      additions++;
      k++;
    }
  }

  const totalLines = Math.max(linesA.length, linesB.length, 1);
  const similarity = Math.max(0, Math.min(100, Math.round((matches / totalLines) * 100)));

  return {
    rows,
    stats: {
      totalLinesA: linesA.length,
      totalLinesB: linesB.length,
      additions,
      deletions,
      modifications,
      matches,
      similarity,
    },
  };
}
