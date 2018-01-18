using System;

namespace Crypto
{
    class Result<TSuccess, TError>
    {
        TSuccess result;
        TError error;

        public State CurrentState { get; }
        public enum State
        {
            Empty = -1,
            Success,
            Error
        }

        Result(TSuccess result, TError error, State currentState)
        {
            this.result = result;
            this.error = error;
            CurrentState = currentState;
        }

        public static Result<TSuccess, TError> Success(TSuccess value)
        {
            return new Result<TSuccess, TError>(value, default(TError), State.Success);
        }

        public static Result<TSuccess, TError> Error(TError value)
        {
            return new Result<TSuccess, TError>(default(TSuccess), value, State.Error);
        }

        public T Match<T>(Func<TSuccess, T> onSuccess, Func<TError, T> onError)
        {
            T returnVal = default(T);
            switch (CurrentState)
            {
                case State.Empty:
                    throw new Exception();
                case State.Success:
                    returnVal = onSuccess(this.result);
                    break;
                case State.Error:
                    returnVal = onError(this.error);
                    break;
            }

            return returnVal;
        }
        public Result<TSuccess, TError> Bind
            (Result<TSuccess, TError> x, Func<TSuccess, Result<TSuccess, TError>> f)
        {
            return x.Match(
                s => f(s),
                e => Error(e)
                );
            throw new Exception();
        }

        public Result<TSuccess, TError> Bind(Func<TSuccess, Result<TSuccess, TError>> f)
        {
            return Match(
                s => f(s),
                e => Error(e)
                );
            throw new Exception();
        }
    }
}

