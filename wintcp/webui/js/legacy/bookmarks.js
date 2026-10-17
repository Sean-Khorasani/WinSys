// legacy/bookmarks.js - Bookmarks and notes

export function bookmarkKey(remote, port) {
  return `${remote}:${port}`;
}

export function isBookmarked(bookmarks, remote, port) {
  return bookmarks.has(bookmarkKey(remote, port));
}

export function toggleBookmark(bookmarks, remote, port) {
  const key = bookmarkKey(remote, port);
  const next = new Set(bookmarks);
  if (next.has(key)) next.delete(key);
  else next.add(key);
  return next;
}
