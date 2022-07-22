using System.Runtime.InteropServices;

namespace AppContainerWrapper
{
    public class SafeHandleBuffer : SafeBuffer
    {
        public SafeHandleBuffer(int size) : base(true)
        {
            Initialize((uint)size);
            handle = Marshal.AllocHGlobal(size);
            BufferSize = size;

        }

        public int BufferSize { get; }

        protected override bool ReleaseHandle()
        {
            if (!IsInvalid)
            {
                Marshal.FreeHGlobal(handle);
                handle = IntPtr.Zero;
            }

            return true;
        }

    }
}