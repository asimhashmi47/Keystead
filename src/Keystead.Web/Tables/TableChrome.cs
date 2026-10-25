using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Microsoft.AspNetCore.WebUtilities;

namespace Keystead.Web.Tables;

/// <summary>Which way a column is currently sorted.</summary>
public enum TableSortState
{
    /// <summary>Not the sort column.</summary>
    None,

    /// <summary>Sorted, smallest first.</summary>
    Ascending,

    /// <summary>Sorted, largest first.</summary>
    Descending,
}

/// <summary>One column, as the header and filter row need it.</summary>
/// <param name="Key">The column key.</param>
/// <param name="Header">The header label.</param>
/// <param name="Align">How the cells line up.</param>
/// <param name="Sortable">Whether the header offers a sort.</param>
/// <param name="Searchable">Whether the filter row offers a box.</param>
/// <param name="Options">A closed set of values, or null for a text box.</param>
/// <param name="Term">The term currently filtering this column, or null.</param>
/// <param name="Sort">Which way it is sorted.</param>
/// <param name="SortUrl">Where the header link goes.</param>
/// <param name="Hint">A short explanation for assistive technology.</param>
/// <param name="Priority">Whether the column survives a narrow table.</param>
public sealed record TableColumnChrome(
    string Key,
    string Header,
    TableAlign Align,
    bool Sortable,
    bool Searchable,
    IReadOnlyList<TableOption>? Options,
    string? Term,
    TableSortState Sort,
    string SortUrl,
    string? Hint,
    TablePriority Priority)
{
    /// <summary>The form field name for this column's filter.</summary>
    public string FieldName => TableQuery.ColumnPrefix + Key;

    /// <summary>The classes a header or body cell in this column carries.</summary>
    /// <remarks>
    /// Emitted on both, because a table cell cannot be hidden from the header alone: the
    /// column would stay in every body row and the two would stop lining up.
    /// </remarks>
    public string CellClass =>
        string.Join(' ', new[]
        {
            Align == TableAlign.End ? "cell--end" : null,
            Priority == TablePriority.Secondary ? "cell--secondary" : null,
            Priority == TablePriority.Hidden ? "cell--hidden" : null,
        }.Where(part => part is not null));
}

/// <summary>
/// Everything the table chrome needs to render: headers, filters, counts and links.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately not generic. The partials that draw a toolbar, a header row and a pager have
/// no business knowing what a row is, and keeping them non-generic is what lets one set of
/// partials serve every table in the application.
/// </para>
/// <para>
/// Every URL here is built once, in one place, from the request's own query string. Pages that
/// each assemble their own sort and page links are pages where one of them quietly drops the
/// filter when you change the sort.
/// </para>
/// </remarks>
public sealed class TableChrome
{
    private readonly string _path;
    private readonly IReadOnlyDictionary<string, string?> _preserved;
    private readonly TableQuery _query;

    internal TableChrome(
        string id,
        string label,
        string path,
        IReadOnlyDictionary<string, string?> preserved,
        TableQuery query,
        int filteredCount,
        int totalCount,
        int pageCount,
        string? exportHandler)
    {
        Id = id;
        Label = label;
        _path = path;
        _preserved = preserved;
        _query = query;
        FilteredCount = filteredCount;
        TotalCount = totalCount;
        PageCount = pageCount;
        ExportHandler = exportHandler;
    }

    /// <summary>A stable id, so the filter form and the table can refer to each other.</summary>
    public string Id { get; }

    /// <summary>What the rows are, in plural and lower case: "members", "secrets".</summary>
    public string Label { get; }

    /// <summary>
    /// The page handler that serves a download, or null when the table offers none.
    /// </summary>
    /// <remarks>
    /// Named by the page rather than assumed, because the handler is what carries the
    /// authorization. A toolbar that linked to a conventional URL would be a toolbar offering a
    /// download from pages that have not written one.
    /// </remarks>
    public string? ExportHandler { get; }

    /// <summary>The id of the filter form these controls submit.</summary>
    public string FormId => $"{Id}-filter";

    /// <summary>The columns, in order.</summary>
    /// <remarks>
    /// Filled in by the engine immediately after construction, because each column's header
    /// link is built from this object's own URL rules. Building them from a second, throwaway
    /// instance is how a sort link ends up dropping a filter the pager keeps.
    /// </remarks>
    public IReadOnlyList<TableColumnChrome> Columns { get; private set; } = [];

    internal void SetColumns(IReadOnlyList<TableColumnChrome> columns) => Columns = columns;

    /// <summary>How many rows match the current search and filters.</summary>
    public int FilteredCount { get; }

    /// <summary>How many rows there are in total.</summary>
    public int TotalCount { get; }

    /// <summary>How many pages the filtered rows fill, at least one.</summary>
    public int PageCount { get; }

    /// <summary>The current page, clamped into range.</summary>
    public int Page => Math.Min(_query.Page, PageCount);

    /// <summary>The page size.</summary>
    public int PageSize => _query.PageSize;

    /// <summary>The page sizes on offer, smallest first.</summary>
    public static IReadOnlyList<int> PageSizes { get; } = [.. TableQuery.PageSizes.Order()];

    /// <summary>The free-text term, or null.</summary>
    public string? Search => _query.Search;

    /// <summary>Whether anything is being searched or filtered.</summary>
    public bool HasFilter => _query.HasFilter;

    /// <summary>Whether the per-column filter row is rendered.</summary>
    public bool FiltersOpen => _query.FiltersOpen;

    /// <summary>Whether closing the filter row is possible, or a term is holding it open.</summary>
    public bool CanCloseFilters => _query.ColumnTerms.Count == 0;

    /// <summary>The URL that opens or closes the per-column filter row.</summary>
    public string FiltersUrl => Build(
        _query,
        page: false,
        extra: FiltersOpen && CanCloseFilters
            ? new Dictionary<string, string?>(StringComparer.Ordinal)
            : new Dictionary<string, string?>(StringComparer.Ordinal) { [TableQuery.FiltersKey] = "1" });

    /// <summary>The hidden field name that keeps the filter row open across a submit.</summary>
    public static string FiltersFieldName => TableQuery.FiltersKey;

    /// <summary>Whether the rows shown are a subset of the rows there are.</summary>
    public bool IsFiltered => FilteredCount != TotalCount;

    /// <summary>The number of the first row on this page, one-based.</summary>
    public int FirstRow => FilteredCount == 0 ? 0 : ((Page - 1) * PageSize) + 1;

    /// <summary>The number of the last row on this page.</summary>
    public int LastRow => Math.Min(Page * PageSize, FilteredCount);

    /// <summary>Whether there is a page before this one.</summary>
    public bool HasPrevious => Page > 1;

    /// <summary>Whether there is a page after this one.</summary>
    public bool HasNext => Page < PageCount;

    /// <summary>The field name for the free-text search box.</summary>
    public static string SearchFieldName => TableQuery.SearchKey;

    /// <summary>The field name for the page size select.</summary>
    public static string SizeFieldName => TableQuery.SizeKey;

    /// <summary>The hidden field name carrying the sort column through the filter form.</summary>
    public static string SortFieldName => TableQuery.SortKey;

    /// <summary>The hidden field name carrying the sort direction.</summary>
    public static string DirectionFieldName => TableQuery.DirectionKey;

    /// <summary>The sort column, or null.</summary>
    public string? Sort => _query.Sort;

    /// <summary>The sort direction as it travels in a URL.</summary>
    public string Direction => _query.Descending ? "desc" : "asc";

    /// <summary>Query-string values the table must carry but does not own.</summary>
    /// <remarks>
    /// A vault page filters by environment with its own control, and the detail panel on the
    /// members page is selected by a query value. Both have to survive a sort or a page
    /// change, and the way they survive is by being rendered as hidden fields in the filter
    /// form and carried in every link built here.
    /// </remarks>
    public IReadOnlyDictionary<string, string?> Preserved => _preserved;

    /// <summary>The URL of another page of the same query.</summary>
    /// <param name="page">The one-based page.</param>
    /// <returns>A relative URL.</returns>
    public string PageUrl(int page) => Build(_query.OnPage(page));

    /// <summary>The URL that clears the search and every column filter.</summary>
    public string ClearUrl => Build(TableQuery.Empty);

    /// <summary>
    /// This exact view, plus one query value of the page's own.
    /// </summary>
    /// <param name="key">The query key.</param>
    /// <param name="value">The value, or null to remove it.</param>
    /// <returns>A relative URL.</returns>
    /// <remarks>
    /// How a row links to its own detail panel. Built from the same rules as every other link
    /// here, so choosing a row keeps the search, the sort and the page it was chosen from.
    /// </remarks>
    public string WithValue(string key, string? value) =>
        Build(_query, extra: new Dictionary<string, string?>(StringComparer.Ordinal) { [key] = value });

    /// <summary>The URL that removes one column's filter and keeps the rest.</summary>
    /// <param name="key">The column key to clear.</param>
    /// <returns>A relative URL.</returns>
    public string WithoutColumn(string key) => Build(_query, drop: key);

    /// <summary>The URL that removes the free-text search and keeps the rest.</summary>
    public string WithoutSearch => Build(_query, dropSearch: true);

    /// <summary>The export URL for a format, carrying the current query.</summary>
    /// <param name="handler">The page handler that exports.</param>
    /// <param name="format">The format key, as the handler expects it.</param>
    /// <returns>A relative URL.</returns>
    public string ExportUrl(string handler, string format) =>
        Build(_query, page: false, extra: new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["handler"] = handler,
            ["format"] = format,
        });

    /// <summary>
    /// Builds the URL a column header links to.
    /// </summary>
    /// <remarks>
    /// Clicking the current sort column reverses it; clicking another sorts by that one,
    /// ascending. Either way the page returns to the first one, because staying on page nine of
    /// a different order shows a page nobody asked for.
    /// </remarks>
    internal string SortUrlFor(string key, bool isCurrent)
    {
        var descending = isCurrent && !_query.Descending;

        var extra = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            [TableQuery.SortKey] = key,
            [TableQuery.DirectionKey] = descending ? "desc" : "asc",
        };

        return Build(_query, page: false, sort: false, extra: extra);
    }

    private string Build(
        TableQuery query,
        bool page = true,
        bool sort = true,
        string? drop = null,
        bool dropSearch = false,
        IReadOnlyDictionary<string, string?>? extra = null)
    {
        var values = new Dictionary<string, string?>(StringComparer.Ordinal);

        foreach (var pair in _preserved)
        {
            values[pair.Key] = pair.Value;
        }

        if (!dropSearch && !string.IsNullOrEmpty(query.Search))
        {
            values[TableQuery.SearchKey] = query.Search;
        }

        foreach (var term in query.ColumnTerms)
        {
            if (!string.Equals(term.Key, drop, StringComparison.OrdinalIgnoreCase))
            {
                values[TableQuery.ColumnPrefix + term.Key] = term.Value;
            }
        }

        if (sort && !string.IsNullOrEmpty(query.Sort))
        {
            values[TableQuery.SortKey] = query.Sort;
            values[TableQuery.DirectionKey] = query.Descending ? "desc" : "asc";
        }

        if (query.PageSize != TableQuery.DefaultPageSize)
        {
            values[TableQuery.SizeKey] = query.PageSize.ToString(CultureInfo.InvariantCulture);
        }

        if (page && query.Page > 1)
        {
            values[TableQuery.PageKey] = query.Page.ToString(CultureInfo.InvariantCulture);
        }

        if (query.ShowFilters)
        {
            values[TableQuery.FiltersKey] = "1";
        }

        if (extra is not null)
        {
            foreach (var pair in extra)
            {
                values[pair.Key] = pair.Value;
            }
        }

        // AddQueryString encodes both halves of every pair, which is the reason the whole URL
        // is assembled here rather than concatenated at each call site.
        return QueryHelpers.AddQueryString(_path, values);
    }
}
