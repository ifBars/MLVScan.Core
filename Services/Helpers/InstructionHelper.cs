using Mono.Cecil.Cil;
using System.ComponentModel;

namespace MLVScan.Services.Helpers
{
    /// <summary>
    /// Provides small IL helper routines used by rules and scanners.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static class InstructionHelper
    {
        /// <summary>
        /// Attempts to recover a small integer argument that was loaded immediately before the current instruction.
        /// </summary>
        /// <param name="instructions">The instruction collection to inspect.</param>
        /// <param name="currentIndex">The instruction index of the target call or operation.</param>
        /// <returns>The recovered integer argument, or <see langword="null"/> if no literal could be found.</returns>
        public static int? ExtractFolderPathArgument(Mono.Collections.Generic.Collection<Instruction> instructions,
            int currentIndex)
        {
            int start = Math.Max(0, currentIndex - 5);
            for (int i = currentIndex - 1; i >= start; i--)
            {
                var instr = instructions[i];

                if (instr.TryResolveInt32Literal(out int value))
                {
                    return value;
                }
            }

            return null;
        }
    }
}
