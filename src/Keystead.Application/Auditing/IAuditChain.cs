using System.Threading;
using System.Threading.Tasks;

namespace Keystead.Application.Auditing;

/// <summary>Appends to, and verifies, the tamper-evident audit chain.</summary>
public interface IAuditChain
{
    /// <summary>
    /// Appends a record to the chain, assigning its sequence number and linking it to the
    /// previous entry.
    /// </summary>
    /// <param name="record">What to record.</param>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The sequence number the entry was written at.</returns>
    Task<long> AppendAsync(AuditRecord record, CancellationToken cancellationToken);

    /// <summary>Walks the whole chain and reports whether it is intact.</summary>
    /// <param name="cancellationToken">Cancels the operation.</param>
    /// <returns>The verification outcome.</returns>
    Task<AuditChainVerification> VerifyAsync(CancellationToken cancellationToken);
}
