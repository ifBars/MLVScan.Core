using Mono.Cecil.Cil;
using System.ComponentModel;

namespace MLVScan.Services
{
    /// <summary>
    /// Builds a small IL snippet around a target instruction for use in findings.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class CodeSnippetBuilder
    {
        /// <summary>
        /// Builds a formatted instruction window centered on the supplied instruction index.
        /// </summary>
        /// <param name="instructions">The instruction collection to format.</param>
        /// <param name="index">The center instruction index.</param>
        /// <param name="contextLines">The number of instructions to include on each side of the center instruction.</param>
        /// <returns>A formatted snippet with the center instruction marked with <c>&gt;&gt;&gt;</c>.</returns>
        public string BuildSnippet(Mono.Collections.Generic.Collection<Instruction> instructions, int index,
            int contextLines)
        {
            var snippetBuilder = new System.Text.StringBuilder();

            for (int j = Math.Max(0, index - contextLines);
                 j < Math.Min(instructions.Count, index + contextLines + 1);
                 j++)
            {
                if (j == index)
                    snippetBuilder.Append(">>> ");
                else
                    snippetBuilder.Append("    ");
                snippetBuilder.AppendLine(instructions[j].ToString());
            }

            return snippetBuilder.ToString().TrimEnd();
        }
    }
}
