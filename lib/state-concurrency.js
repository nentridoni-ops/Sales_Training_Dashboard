export function stateVersionMatches(currentEtag, expectedEtag) {
  return currentEtag === expectedEtag;
}

export function stateBlobWriteOptions(expectedEtag) {
  return expectedEtag === null
    ? { allowOverwrite: false }
    : { ifMatch: expectedEtag, allowOverwrite: true };
}

export function hasValidExpectedStateVersion(body) {
  return Boolean(body && typeof body === 'object' &&
    Object.hasOwn(body, 'expectedEtag') &&
    (body.expectedEtag === null ||
      (typeof body.expectedEtag === 'string' && body.expectedEtag.length > 0)));
}

export function isBlobPreconditionFailure(error) {
  return error?.name === 'BlobPreconditionFailedError' ||
    error?.status === 412 || error?.statusCode === 412 ||
    /(?:precondition failed|etag mismatch)/i.test(String(error?.message || ''));
}

export function stateConflict(res, message = 'State berubah sejak terakhir dibaca. Muat ulang data sebelum mencoba lagi.') {
  return res.status(409).json({
    ok: false,
    error: 'state_conflict',
    code: 'STATE_CONFLICT',
    message,
    reloadRequired: true
  });
}
