import { type Readable } from 'stream';

import { isDefined } from 'twenty-shared/utils';

type ReadableWithSource = Readable & { source?: Readable };

// AWS SDK stream wrappers (ChecksumStream and kin) do not propagate destroy()
// to the response stream they wrap, which strands the socket in the agent's
// pool. Destroying the exposed source alongside the wrapper releases it.
export const destroyReadableWithSource = (stream: Readable): void => {
  stream.destroy();

  const source = (stream as ReadableWithSource).source;

  if (isDefined(source) && !source.destroyed) {
    source.destroy();
  }
};
