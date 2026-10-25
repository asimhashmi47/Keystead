using System;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Microsoft.AspNetCore.Http;

namespace Keystead.Web.Tables;

/// <summary>
/// What the person asked a table for: a search, per-column terms, a sort and a page.
/// </summary>
/// <remarks>
/// <para>
/// Read straight from the query string rather than model-bound, and every value is clamped on
/// the way in. That is deliberate: this type is the only thing between a URL anyone can edit
/// and a sort, a filter and a page size. Model binding would hand back whatever was asked for
/// and leave each page to decide what to do with <c>size=100000</c> or <c>sort=../../etc</c>.
/// Here there is one answer, written once.
/// </para>
/// <para>
/// Nothing in here can fail. A malformed page is page one, an unknown sort key is no sort, an
/// over-long term is truncated. A table is a read; refusing to render one because a URL was
/// odd would be a worse answer than rendering the first page.
/// </para>
/// </remarks>
public sealed class TableQuery
{
    /// <summary>The query-string key carrying the free-text search.</summary>
    public const string SearchKey = "q";

    /// <summary>The query-string key carrying the sort column.</summary>
    public const string SortKey = "sort";

    /// <summary>The query-string key carrying the sort direction.</summary>
    public const string DirectionKey = "dir";

    /// <summary>The query-string key carrying the page number.</summary>
    public const string PageKey = "page";

    /// <summary>The query-string key carrying the page size.</summary>
    public const string SizeKey = "size";

    /// <summary>The prefix on a per-column term, as in <c>c.name=stripe</c>.</summary>
    public const string ColumnPrefix = "c.";

    /// <summary>The query-string key that opens the per-column filter row.</summary>
    public const string FiltersKey = "filters";

    /// <summary>The longest search term accepted; anything longer is truncated.</summary>
    public const int MaxTermLength = 200;

    /// <summary>The page sizes offered.</summary>
    public static readonly FrozenSet<int> PageSizes = new[] { 10, 25, 50, 100 }.ToFrozenSet();

    /// <summary>The page size used when none was asked for.</summary>
    public const int DefaultPageSize = 25;

    /// <summary>An empty query: no search, no sort, first page.</summary>
    public static TableQuery Empty { get; } = new();

    /// <summary>The free-text term, or null.</summary>
    public string? Search { get; private init; }

    /// <summary>Per-column terms, keyed by column key. Never null.</summary>
    public IReadOnlyDictionary<string, string> ColumnTerms { get; private init; } =
        FrozenDictionary<string, string>.Empty;

    /// <summary>The column key to sort by, or null for the table's own order.</summary>
    public string? Sort { get; private init; }

    /// <summary>Whether the sort is descending.</summary>
    public bool Descending { get; private init; }

    /// <summary>The one-based page number.</summary>
    public int Page { get; private init; } = 1;

    /// <summary>How many rows a page holds.</summary>
    public int PageSize { get; private init; } = DefaultPageSize;

    /// <summary>
    /// Whether the per-column filter row is open.
    /// </summary>
    /// <remarks>
    /// A query value rather than a script toggle, for three reasons: it works with scripting
    /// blocked, the state travels in a shared link alongside the filters it belongs to, and
    /// there is one place that decides whether the row is rendered instead of two that have to
    /// agree. A row with a term in it is always open, because hiding an active filter is how
    /// someone concludes the table is broken.
    /// </remarks>
    public bool ShowFilters { get; private init; }

    /// <summary>Whether anything is being searched or filtered.</summary>
    public bool HasFilter => !string.IsNullOrEmpty(Search) || ColumnTerms.Count > 0;

    /// <summary>Whether the filter row should be rendered.</summary>
    public bool FiltersOpen => ShowFilters || ColumnTerms.Count > 0;

    /// <summary>
    /// Reads a query from the request.
    /// </summary>
    /// <param name="request">The current request.</param>
    /// <returns>The clamped query.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="request"/> is null.</exception>
    public static TableQuery FromRequest(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var columns = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var pair in request.Query)
        {
            if (!pair.Key.StartsWith(ColumnPrefix, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var key = pair.Key[ColumnPrefix.Length..];
            var term = Term(pair.Value.ToString());

            // A column term left empty is not a filter that matches nothing; it is no filter.
            // Otherwise clearing a box and pressing Filter would empty the table.
            if (key.Length > 0 && term is not null)
            {
                columns[key] = term;
            }
        }

        return new TableQuery
        {
            Search = Term(request.Query[SearchKey].ToString()),
            ColumnTerms = columns.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase),
            Sort = Term(request.Query[SortKey].ToString()) is { } sort ? Sanitize(sort) : null,
            Descending = string.Equals(
                request.Query[DirectionKey].ToString(),
                "desc",
                StringComparison.OrdinalIgnoreCase),
            Page = PositiveOrOne(request.Query[PageKey].ToString()),
            PageSize = Size(request.Query[SizeKey].ToString()),
            ShowFilters = request.Query[FiltersKey].ToString() is "1" or "true",
        };
    }

    /// <summary>Returns this query moved to another page.</summary>
    /// <param name="page">The one-based page.</param>
    /// <returns>A new query.</returns>
    public TableQuery OnPage(int page) =>
        new()
        {
            Search = Search,
            ColumnTerms = ColumnTerms,
            Sort = Sort,
            Descending = Descending,
            Page = Math.Max(1, page),
            PageSize = PageSize,
            ShowFilters = ShowFilters,
        };

    /// <summary>Returns the term for a column, or null.</summary>
    /// <param name="key">The column key.</param>
    /// <returns>The term, or null when the column is not filtered.</returns>
    public string? TermFor(string key) =>
        key is not null && ColumnTerms.TryGetValue(key, out var term) ? term : null;

    private static string? Term(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var trimmed = raw.Trim();

        return trimmed.Length > MaxTermLength ? trimmed[..MaxTermLength] : trimmed;
    }

    /// <summary>
    /// Strips a sort key down to what a column key can contain.
    /// </summary>
    /// <remarks>
    /// The value is matched against a closed list of columns later and an unknown key is
    /// ignored, so this is belt and braces. It is here anyway because a sort key is echoed
    /// back into links and labels, and a value that cannot contain punctuation is one fewer
    /// thing to think about every time it is.
    /// </remarks>
    private static string Sanitize(string sort) =>
        new([.. sort.Where(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_')]);

    private static int PositiveOrOne(string? raw) =>
        int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var page)
        && page > 0
            ? page
            : 1;

    private static int Size(string? raw) =>
        int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var size)
        && PageSizes.Contains(size)
            ? size
            : DefaultPageSize;
}
