using System;
using System.Collections.Generic;

namespace Keystead.Web.Tables;

/// <summary>How a column's cells line up.</summary>
public enum TableAlign
{
    /// <summary>The default.</summary>
    Start,

    /// <summary>Numbers and anything read by comparing magnitudes.</summary>
    End,
}

/// <summary>How much a column earns its place when space is short.</summary>
public enum TablePriority
{
    /// <summary>Always rendered.</summary>
    Essential,

    /// <summary>
    /// Dropped when the table is rendered somewhere narrow, such as beside an open detail
    /// panel, or on a phone.
    /// </summary>
    /// <remarks>
    /// Dropped from the rendered table only. The column keeps its filter, its sort and its
    /// place in an export, because those are about the data rather than about how much room
    /// the browser has. A column should only be secondary when something else on screen
    /// already says the same thing: the detail panel, or the cell beside it.
    /// </remarks>
    Secondary,

    /// <summary>
    /// Never rendered, but still filtered, sorted and exported.
    /// </summary>
    /// <remarks>
    /// For a value that belongs in a spreadsheet and not on a screen. The audit log's detail
    /// is the example: on screen it is a column of empty cells with an occasional paragraph in
    /// it, and in a downloaded file it is the column a reviewer reads after filtering to the
    /// refusals.
    /// </remarks>
    Hidden,
}

/// <summary>One choice in a column's filter.</summary>
/// <param name="Value">What the filter compares against, exactly.</param>
/// <param name="Label">What the person reads.</param>
public sealed record TableOption(string Value, string Label);

/// <summary>
/// One column of a table: what it is called, what it holds, and how it is searched and sorted.
/// </summary>
/// <typeparam name="T">The row type.</typeparam>
/// <remarks>
/// <para>
/// A column is declared once and then used for four things: the header, the per-column filter,
/// the sort, and the export. That is the point of the type. Searching a column the export does
/// not include, or exporting a column nobody can sort, is the sort of drift that happens when
/// each of those is written separately in each page.
/// </para>
/// <para>
/// <see cref="Text"/> is what the column *means* as text, which is not always what the cell
/// renders. A status cell draws a badge; its text is still "Active", because that is what
/// someone typing in the filter box will type and what belongs in a spreadsheet.
/// </para>
/// </remarks>
public sealed class TableColumn<T>
{
    /// <summary>
    /// The key used in URLs, as in <c>c.name=stripe</c> and <c>sort=name</c>.
    /// </summary>
    /// <remarks>Lower case, letters, digits and hyphens. It is part of a shareable URL.</remarks>
    public required string Key { get; init; }

    /// <summary>The header label.</summary>
    public required string Header { get; init; }

    /// <summary>
    /// The column's value as text: what is searched, what is sorted when no
    /// <see cref="SortBy"/> is given, and what is exported.
    /// </summary>
    public required Func<T, string> Text { get; init; }

    /// <summary>
    /// A typed sort key, for columns where the text does not sort correctly.
    /// </summary>
    /// <remarks>
    /// "9" after "10", "1 Feb" after "20 Jan". Any column whose text is a number or a date
    /// needs this, and leaving it out is the most likely way to get a table that looks right
    /// and is ordered wrongly.
    /// </remarks>
    public Func<T, IComparable?>? SortBy { get; init; }

    /// <summary>Whether this column takes part in search and filtering.</summary>
    public bool Searchable { get; init; } = true;

    /// <summary>Whether the header offers a sort.</summary>
    public bool Sortable { get; init; } = true;

    /// <summary>Whether the column appears in an export.</summary>
    public bool Exported { get; init; } = true;

    /// <summary>How the cells line up.</summary>
    public TableAlign Align { get; init; }

    /// <summary>Whether the cells hold figures, which get tabular numerals.</summary>
    public bool Numeric { get; init; }

    /// <summary>
    /// A closed set of values, which turns the column's filter into a select.
    /// </summary>
    /// <remarks>
    /// Present means the filter is an exact match rather than a substring, which is what a
    /// status or a role wants: filtering a role column for "admin" should not also return
    /// "Administrator of nothing" from some future label.
    /// </remarks>
    public IReadOnlyList<TableOption>? Options { get; init; }

    /// <summary>A short explanation shown to assistive technology on the header.</summary>
    public string? Hint { get; init; }

    /// <summary>Whether the column survives a narrow table.</summary>
    public TablePriority Priority { get; init; }

    /// <summary>Reads this column's text for a row, never returning null.</summary>
    /// <param name="row">The row.</param>
    /// <returns>The text, or an empty string.</returns>
    public string TextOf(T row) => Text(row) ?? string.Empty;
}
