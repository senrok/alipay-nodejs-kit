class Result<T, E extends Error> {
  private readonly result?: T
  private readonly error?: E
  constructor({ result, error }: { result?: T; error?: E }) {
    this.result = result
    this.error = error
  }

  unwrap(): T {
    if (this.error) {
      throw this.error
    }
    return this.result as T
  }
}
