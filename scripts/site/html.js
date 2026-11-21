// SPDX-License-Identifier: Apache-2.0 OR MIT
// HTML helpers of the site build.

/**
 * @param {unknown} text
 * @returns {string}
 */
export function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
