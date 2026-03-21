using Mono.Cecil.Cil;
using System.ComponentModel;

namespace MLVScan.Services.Helpers
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static class InstructionHelper
    {
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
