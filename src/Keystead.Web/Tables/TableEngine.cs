using System;
using System.Collections.Generic;
using System.Linq;

namespace Keystead.Web.Tables;

/// <summary>
/// A table's rows and the chrome that describes them.
/// </summary>
/// <typeparam name="T">The row type.</typeparam>
public sealed class TableView<T>
{
    internal TableView(
        IReadOnlyList<T> rows,
        IReadOnlyList<T> matched,
        IReadOnlyList<TableColumn<T>> columns,
        TableChrome chrome)
    {
        Rows = rows;
        Matched = matched;
        Columns = columns;
        Chrome = chrome;
    }

    /// <summary>The rows on this page, in order.</summary>
    public IReadOnlyList<T> Rows { get; }

    /// <summary>
    /// Every row matching the current search and filters, across all pages.
    /// </summary>
    /// <remarks>
    /// What an export writes. Exporting the visible page only would be a surprise: someone who
    /// filtered to forty rows and pressed Export expects forty rows, not the twenty-five the
    /// page happened to show.
    /// </remarks>
    public IReadOnlyList<T> Matched { get; }

    /// <summary>The columns, in order.</summary>
    public IReadOnlyList<TableColumn<T>> Columns { get; }

    /// <summary>The headers, filters, counts and links.</summary>
    public TableChrome Chrome { get; }

    /// <summary>Whether this page has no rows.</summary>
    public bool IsEmpty => Rows.Count == 0;
}

/// <summary>
/// Searches, filters, sorts and pages a list of rows.
/// </summary>
/// <remarks>
/// <para>
/// In memory, on purpose. Every table this serves is a workspace-scoped list the page has
/// already loaded and already authorized: members, vaults, the secrets in one vault, service
/// identities, sessions. Pushing the filter into the database would mean each of those queries
/// learning about sort keys and term matching, and would move the authorization boundary into
/// the same expression as a user-supplied string. The audit log, which is the one table that
/// can grow without limit, keeps its own server-side filter and paging and uses
/// <see cref="FromServer"/> for the chrome.
/// </para>
/// <para>
/// Nothing here can throw on bad input. An unknown sort key sorts by nothing, a page past the
/// end shows the last page, and a column whose value selector throws is the page's bug to fix,
/// not something to be guessed at here.
/// </para>
/// </remarks>
public static class TableEngine
{
    /// <summary>
    /// Builds a view over a list of rows.
    /// </summary>
    /// <typeparam name="T">The row type.</typeparam>
    /// <param name="rows">Every row the person may see.</param>
    /// <param name="columns">The columns.</param>
    /// <param name="query">What was asked for.</param>
    /// <param name="id">A stable id for the table's chrome.</param>
    /// <param name="label">What the rows are, in plural: "members".</param>
    /// <param name="path">The page's own path, for building links.</param>
    /// <param name="preserved">Query values the table must carry but does not own.</param>
    /// <param name="exportHandler">
    /// The page handler serving a download, or null when the table offers none.
    /// </param>
    /// <returns>The view.</returns>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public static TableView<T> Build<T>(
        IReadOnlyList<T> rows,
        IReadOnlyList<TableColumn<T>> columns,
        TableQuery query,
        string id,
        string label,
        string path,
        IReadOnlyDictionary<string, string?>? preserved = null,
        string? exportHandler = "Export")
    {
        ArgumentNullException.ThrowIfNull(rows);
        ArgumentNullException.ThrowIfNull(columns);
        ArgumentNullException.ThrowIfNull(query);
        ArgumentException.ThrowIfNullOrEmpty(id);
        ArgumentException.ThrowIfNullOrEmpty(label);
        ArgumentNullException.ThrowIfNull(path);

        var matched = Sort(Filter(rows, columns, query), columns, query);

        var pageCount = Math.Max(1, (matched.Count + query.PageSize - 1) / query.PageSize);
        var page = Math.Min(Math.Max(1, query.Page), pageCount);

        var paged = matched
            .Skip((page - 1) * query.PageSize)
            .Take(query.PageSize)
            .ToList();

        var chrome = new TableChrome(
            id,
            label,
            path,
            preserved ?? new Dictionary<string, string?>(StringComparer.Ordinal),
            query,
            matched.Count,
            rows.Count,
            pageCount,
            exportHandler);

        chrome.SetColumns([.. columns.Select(column => Describe(column, query, chrome))]);

        return new TableView<T>(paged, matched, columns, chrome);
    }

    /// <summary>
    /// Builds a view over rows a server has already filtered, sorted and paged.
    /// </summary>
    /// <typeparam name="T">The row type.</typeparam>
    /// <param name="rows">The rows on this page, as the query returned them.</param>
    /// <param name="columns">The columns.</param>
    /// <param name="query">What was asked for.</param>
    /// <param name="id">A stable id for the table's chrome.</param>
    /// <param name="label">What the rows are, in plural.</param>
    /// <param name="path">The page's own path, for building links.</param>
    /// <param name="filteredCount">How many rows match, across all pages.</param>
    /// <param name="totalCount">How many rows there are in total.</param>
    /// <param name="preserved">Query values the table must carry but does not own.</param>
    /// <param name="exportHandler">The page handler serving a download, or null.</param>
    /// <returns>The view.</returns>
    /// <remarks>
    /// <para>
    /// For the audit log, which is the one table here that grows without limit. Loading it to
    /// filter it in memory would mean reading the whole history to render twenty-five rows, so
    /// its query does the work and this builds the same chrome around the result.
    /// </para>
    /// <para>
    /// The caller is responsible for honouring the query it was given. Nothing here can check
    /// that, which is the cost of the arrangement and the reason it is not the default.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public static TableView<T> FromServer<T>(
        IReadOnlyList<T> rows,
        IReadOnlyList<TableColumn<T>> columns,
        TableQuery query,
        string id,
        string label,
        string path,
        int filteredCount,
        int totalCount,
        IReadOnlyDictionary<string, string?>? preserved = null,
        string? exportHandler = "Export")
    {
        ArgumentNullException.ThrowIfNull(rows);
        ArgumentNullException.ThrowIfNull(columns);
        ArgumentNullException.ThrowIfNull(query);
        ArgumentException.ThrowIfNullOrEmpty(id);
        ArgumentException.ThrowIfNullOrEmpty(label);
        ArgumentNullException.ThrowIfNull(path);

        var pageCount = Math.Max(1, (filteredCount + query.PageSize - 1) / query.PageSize);

        var chrome = new TableChrome(
            id,
            label,
            path,
            preserved ?? new Dictionary<string, string?>(StringComparer.Ordinal),
            query,
            filteredCount,
            totalCount,
            pageCount,
            exportHandler);

        chrome.SetColumns([.. columns.Select(column => Describe(column, query, chrome))]);

        return new TableView<T>(rows, rows, columns, chrome);
    }

    private static TableColumnChrome Describe<T>(
        TableColumn<T> column,
        TableQuery query,
        TableChrome chrome)
    {
        var isCurrent = string.Equals(query.Sort, column.Key, StringComparison.OrdinalIgnoreCase);

        var state = (isCurrent, query.Descending) switch
        {
            (true, true) => TableSortState.Descending,
            (true, false) => TableSortState.Ascending,
            _ => TableSortState.None,
        };

        return new TableColumnChrome(
            column.Key,
            column.Header,
            column.Align,
            column.Sortable,
            column.Searchable,
            column.Options,
            query.TermFor(column.Key),
            state,
            chrome.SortUrlFor(column.Key, isCurrent),
            column.Hint,
            column.Priority);
    }

    private static List<T> Filter<T>(
        IReadOnlyList<T> rows,
        IReadOnlyList<TableColumn<T>> columns,
        TableQuery query)
    {
        if (!query.HasFilter)
        {
            return [.. rows];
        }

        var searchable = columns.Where(c => c.Searchable).ToList();

        // Terms naming a column that does not exist are ignored rather than treated as a filter
        // nothing can satisfy, so an old bookmark shows a table instead of an empty one.
        var termed = query.ColumnTerms
            .Select(term => (
                Column: columns.FirstOrDefault(c =>
                    c.Searchable && string.Equals(c.Key, term.Key, StringComparison.OrdinalIgnoreCase)),
                term.Value))
            .Where(pair => pair.Column is not null)
            .ToList();

        var result = new List<T>(rows.Count);

        foreach (var row in rows)
        {
            if (!MatchesSearch(row, searchable, query.Search))
            {
                continue;
            }

            var matchesColumns = true;

            foreach (var (column, term) in termed)
            {
                if (!MatchesColumn(row, column!, term))
                {
                    matchesColumns = false;
                    break;
                }
            }

            if (matchesColumns)
            {
                result.Add(row);
            }
        }

        return result;
    }

    private static bool MatchesSearch<T>(
        T row,
        IReadOnlyList<TableColumn<T>> searchable,
        string? search)
    {
        if (string.IsNullOrEmpty(search))
        {
            return true;
        }

        foreach (var column in searchable)
        {
            if (column.TextOf(row).Contains(search, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Whether one row satisfies one column's term.
    /// </summary>
    /// <remarks>
    /// A column with a closed set of options matches exactly; everything else matches as a
    /// substring. Exact matching for an option column is what stops a status filter for
    /// "Active" from also returning "Inactive", which substring matching cheerfully does.
    /// </remarks>
    private static bool MatchesColumn<T>(T row, TableColumn<T> column, string term)
    {
        var text = column.TextOf(row);

        return column.Options is null
            ? text.Contains(term, StringComparison.OrdinalIgnoreCase)
            : string.Equals(text, term, StringComparison.OrdinalIgnoreCase);
    }

    private static List<T> Sort<T>(
        List<T> rows,
        IReadOnlyList<TableColumn<T>> columns,
        TableQuery query)
    {
        if (string.IsNullOrEmpty(query.Sort))
        {
            return rows;
        }

        var column = columns.FirstOrDefault(c =>
            c.Sortable && string.Equals(c.Key, query.Sort, StringComparison.OrdinalIgnoreCase));

        if (column is null)
        {
            // An unknown or unsortable key leaves the list in the order the page chose, which
            // for every table here is already the most useful default.
            return rows;
        }

        // OrderBy is a stable sort, so rows that tie keep the order the page put them in
        // instead of shuffling between requests.
        var ordered = column.SortBy is { } sortBy
            ? query.Descending
                ? rows.OrderByDescending(row => sortBy(row), NullsLast.Descending)
                : rows.OrderBy(row => sortBy(row), NullsLast.Ascending)
            : query.Descending
                ? rows.OrderByDescending(column.TextOf, StringComparer.OrdinalIgnoreCase)
                : rows.OrderBy(column.TextOf, StringComparer.OrdinalIgnoreCase);

        return [.. ordered];
    }

    /// <summary>
    /// Comparers that keep rows with no value at the bottom, whichever way the sort runs.
    /// </summary>
    /// <remarks>
    /// "Never used" is not a very old date and not a very recent one; it is the absence of one.
    /// Sorting a last-used column either way should put the rows that have a value first,
    /// because those are the rows the sort was about. Since OrderByDescending reverses whatever
    /// the comparer says, the two directions need opposite answers for null to land in the same
    /// place both times.
    /// </remarks>
    private static class NullsLast
    {
        /// <summary>For an ascending sort: null counts as the largest value.</summary>
        public static IComparer<IComparable?> Ascending { get; } = new Comparer(nullIsLargest: true);

        /// <summary>For a descending sort: null counts as the smallest value.</summary>
        public static IComparer<IComparable?> Descending { get; } = new Comparer(nullIsLargest: false);

        private sealed class Comparer : IComparer<IComparable?>
        {
            private readonly bool _nullIsLargest;

            public Comparer(bool nullIsLargest) => _nullIsLargest = nullIsLargest;

            public int Compare(IComparable? x, IComparable? y)
            {
                if (x is null && y is null)
                {
                    return 0;
                }

                if (x is null)
                {
                    return _nullIsLargest ? 1 : -1;
                }

                if (y is null)
                {
                    return _nullIsLargest ? -1 : 1;
                }

                // Values of different shapes cannot be ordered against each other, and a
                // column that produces them is a bug in that column rather than a reason to
                // fail the page.
                return x.GetType() == y.GetType() ? x.CompareTo(y) : 0;
            }
        }
    }
}
