import { PassThrough, Readable } from 'stream';

import { destroyReadableWithSource } from 'src/utils/destroy-readable-with-source.util';

describe('destroyReadableWithSource', () => {
  it('destroys a plain stream', () => {
    const stream = new PassThrough();

    destroyReadableWithSource(stream);

    expect(stream.destroyed).toBe(true);
  });

  it('destroys the wrapped source a wrapper does not propagate to', () => {
    const source = new PassThrough();
    const wrapper = new PassThrough() as PassThrough & { source: Readable };

    wrapper.source = source;

    destroyReadableWithSource(wrapper);

    expect(wrapper.destroyed).toBe(true);
    expect(source.destroyed).toBe(true);
  });

  it('leaves an already-destroyed source alone', () => {
    const source = new PassThrough();

    source.destroy();
    const destroySpy = jest.spyOn(source, 'destroy');
    const wrapper = new PassThrough() as PassThrough & { source: Readable };

    wrapper.source = source;

    destroyReadableWithSource(wrapper);

    expect(destroySpy).not.toHaveBeenCalled();
  });
});
