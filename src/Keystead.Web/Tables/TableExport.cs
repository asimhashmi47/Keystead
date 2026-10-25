using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using Microsoft.AspNetCore.Mvc;

namespace Keystead.Web.Tables;

/// <summary>The formats a table can be downloaded in.</summary>
public enum TableExportFormat
{
    /// <summary>An Office Open XML workbook.</summary>
    Excel,

    /// <summary>Comma separated values.</summary>
    Csv,
}

/// <summary>
/// Turns a filtered table into a file.
/// </summary>
/// <remarks>
/// <para>
/// The export is built from the same <see cref="TableColumn{T}"/> list the page renders, so a
/// spreadsheet holds what the screen held: the same columns, in the same order, after the same
/// search and the same filters, in the same sort. An export assembled separately is an export
/// that drifts, and the version people trust is whichever one they opened last.
/// </para>
/// <para>
/// A column can opt out with <c>Exported = false</c>. That is how an actions column, which is
/// a row of buttons rather than a value, stays out of the file. Nothing opts *in* to being
/// exported, because a column that holds a value worth showing on screen is a value worth
/// taking away.
/// </para>
/// <para>
/// There is nothing to exclude here beyond that. A secret value is never in a column, in any
/// table, because it is never loaded for a list in the first place: only the reveal handler
/// returns one, by <c>POST</c>, after a step-up. An export cannot leak what the page model does
/// not hold.
/// </para>
/// </remarks>
public static class TableExport
{
    /// <summary>The most rows a single file will carry.</summary>
    /// <remarks>
    /// A ceiling rather than a page, so an export is the whole filtered set in every ordinary
    /// case and a bounded file in the one case it is not. The alternative — streaming
    /// everything — turns one URL into an unbounded amount of work for whoever requests it.
    /// </remarks>
    public const int MaxRows = 10_000;

    /// <summary>Reads a format from a query value, defaulting to a workbook.</summary>
    /// <param name="value">The <c>format</c> query value.</param>
    /// <returns>The format.</returns>
    public static TableExportFormat ParseFormat(string? value) =>
        string.Equals(value, "csv", StringComparison.OrdinalIgnoreCase)
            ? TableExportFormat.Csv
            : TableExportFormat.Excel;

    /// <summary>
    /// Builds the download for a view.
    /// </summary>
    /// <typeparam name="T">The row type.</typeparam>
    /// <param name="view">The filtered, sorted view.</param>
    /// <param name="format">The format asked for.</param>
    /// <param name="sheetName">The sheet name, and the stem of the file name.</param>
    /// <returns>A file result.</returns>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public static FileContentResult ToFile<T>(
        TableView<T> view,
        TableExportFormat format,
        string sheetName)
    {
        ArgumentNullException.ThrowIfNull(view);
        ArgumentException.ThrowIfNullOrEmpty(sheetName);

        var columns = view.Columns.Where(column => column.Exported).ToList();
        var headers = columns.Select(column => column.Header).ToList();

        var rows = view.Matched
            .Take(MaxRows)
            .Select(row => (IReadOnlyList<string>)[.. columns.Select(column => column.TextOf(row))])
            .ToList();

        var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);
        var stem = FileStem(sheetName);

        return format is TableExportFormat.Csv
            ? new FileContentResult(Csv(headers, rows), "text/csv; charset=utf-8")
            {
                FileDownloadName = $"keystead-{stem}-{stamp}.csv",
            }
            : new FileContentResult(
                XlsxWorkbook.Create(sheetName, headers, rows),
                XlsxWorkbook.ContentType)
            {
                FileDownloadName = $"keystead-{stem}-{stamp}.xlsx",
            };
    }

    private static byte[] Csv(
        IReadOnlyList<string> headers,
        IReadOnlyList<IReadOnlyList<string>> rows)
    {
        var csv = new StringBuilder();

        csv.AppendLine(string.Join(',', headers.Select(Cell)));

        foreach (var row in rows)
        {
            csv.AppendLine(string.Join(',', row.Select(Cell)));
        }

        // A byte order mark, because Excel opening a UTF-8 CSV without one mangles every
        // non-ASCII name in it. The workbook format needs no such apology.
        return [.. Encoding.UTF8.GetPreamble(), .. Encoding.UTF8.GetBytes(csv.ToString())];
    }

    /// <summary>
    /// Quotes one CSV field, and defuses it as a formula.
    /// </summary>
    /// <remarks>
    /// A field opening with <c>=</c>, <c>+</c>, <c>-</c> or <c>@</c> is a formula to a
    /// spreadsheet, and these fields carry names, addresses and user agents that someone else
    /// chose. The workbook export has no equivalent guard because it writes string cells, which
    /// are never evaluated; this one needs it.
    /// </remarks>
    private static string Cell(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "\"\"";
        }

        var guarded = value[0] is '=' or '+' or '-' or '@' or '\t' or '\r'
            ? "'" + value
            : value;

        return "\"" + guarded.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }

    /// <summary>
    /// Reduces a sheet name to something safe in a <c>Content-Disposition</c> header.
    /// </summary>
    private static string FileStem(string sheetName)
    {
        var stem = new StringBuilder(sheetName.Length);

        foreach (var character in sheetName.ToLowerInvariant())
        {
            if (char.IsAsciiLetterOrDigit(character))
            {
                stem.Append(character);
            }
            else if (stem.Length > 0 && stem[^1] != '-')
            {
                stem.Append('-');
            }
        }

        return stem.ToString().Trim('-') is { Length: > 0 } cleaned ? cleaned : "export";
    }
}
