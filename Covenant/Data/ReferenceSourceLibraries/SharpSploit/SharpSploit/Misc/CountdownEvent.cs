// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Threading;

namespace SharpSploit.Misc
{
    /// <summary>
    /// CountdownEvent is used for counting Asynchronous operations
    /// </summary>
    /// <remarks>
    /// Adapted from https://stackoverflow.com/questions/6790499
    /// </remarks>
    public sealed class CountdownEvent : IDisposable
    {
        private readonly ManualResetEvent _countEvent = new ManualResetEvent(false);
        private readonly ManualResetEvent _reachedCountEvent = new ManualResetEvent(false);
        private volatile int _maxCount;
        private volatile int _currentCount = 0;
        private volatile bool _isDisposed = false;

        public CountdownEvent(int count)
        {
            this._maxCount = count;
        }

        public bool Signal()
        {
            if (this._isDisposed)
            {
                return false;
            }
            if (this._currentCount >= this._maxCount)
            {
                return true;
            }
            if (Interlocked.Increment(ref _currentCount) >= this._maxCount)
            {
                _reachedCountEvent.Set();
                return true;
            }
            _countEvent.Set();
            return false;
        }

        public bool Wait(int timeout = Timeout.Infinite)
        {
            if (this._isDisposed)
            {
                return false;
            }
            return _reachedCountEvent.WaitOne(timeout);
        }

        public bool WaitOne(int timeout = Timeout.Infinite)
        {
            if (this._isDisposed)
            {
                return false;
            }
            return _countEvent.WaitOne(timeout);
        }

        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        public void Dispose(bool disposing)
        {
            if (!this._isDisposed)
            {
                if (disposing)
                {
                    ((IDisposable)_reachedCountEvent).Dispose();
                    ((IDisposable)_countEvent).Dispose();
                }
                this._isDisposed = true;
            }
        }
    }
}
