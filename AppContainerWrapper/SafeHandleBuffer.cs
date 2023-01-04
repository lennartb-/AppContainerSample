using System.Runtime.InteropServices;

namespace AppContainerWrapper;

/// <summary>
/// Implementation of a <see cref="SafeBuffer"/> that manages an unsafe <see cref="IntPtr"/>.
/// </summary>
public class SafeHandleBuffer : SafeBuffer
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SafeHandleBuffer"/> class.
    /// </summary>
    /// <param name="size">The size of the buffer.</param>
    public SafeHandleBuffer(int size)
        : base(true)
    {
        Initialize((uint)size);
        handle = Marshal.AllocHGlobal(size);
        BufferSize = size;
    }

    /// <summary>
    /// Gets the size of the buffer.
    /// </summary>
    public int BufferSize { get; }

    /// <inheritdoc />
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