using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace Keystead.Web.Tables;

/// <summary>
/// Writes a single-sheet Office Open XML workbook: a real <c>.xlsx</c>, not a renamed CSV.
/// </summary>
/// <remarks>
/// <para>
/// A CSV named <c>.xlsx</c> is the usual shortcut and it is worse than it looks: Excel shows a
/// repair prompt, Numbers refuses it, and the person who asked for a spreadsheet concludes the
/// export is broken. A minimal workbook is a handful of XML parts in a zip, which is less code
/// than a dependency and no supply chain to audit.
/// </para>
/// <para>
/// <b>Why there is no formula to inject.</b> Every cell is written as an inline string
/// (<c>t="inlineStr"</c>), which Excel renders as text whatever it contains. A leading
/// <c>=</c> in a value is displayed, not evaluated. That matters here more than in most
/// applications: the audit log carries user agents and resource labels that a caller chooses,
/// and the audit log is precisely the file a security reviewer opens. The CSV export has to
/// prefix those values to defend itself; this format does not, because a string cell is never
/// a formula cell.
/// </para>
/// <para>
/// <b>What is not supported, deliberately.</b> One sheet, strings only, a frozen bold header
/// row, an auto-filter and per-column widths. No number formats, no formulas, no styles beyond
/// the header. A spreadsheet of rows people sort and filter needs exactly that, and every
/// feature past it is another part to get wrong.
/// </para>
/// </remarks>
public static class XlsxWorkbook
{
    /// <summary>The media type browsers and Excel expect.</summary>
    public const string ContentType =
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

    /// <summary>The widest a generated column is allowed to be, in characters.</summary>
    private const int MaxColumnWidth = 60;

    /// <summary>The narrowest, so a short header still has room for its filter arrow.</summary>
    private const int MinColumnWidth = 10;

    /// <summary>The most columns a sheet may have, which is the format's own limit.</summary>
    private const int MaxColumns = 16_384;

    /// <summary>
    /// Builds a workbook.
    /// </summary>
    /// <param name="sheetName">The sheet's name, cleaned of the characters Excel forbids.</param>
    /// <param name="headers">The header row.</param>
    /// <param name="rows">The body rows. Short rows are padded, long ones are truncated.</param>
    /// <returns>The file's bytes.</returns>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    public static byte[] Create(
        string sheetName,
        IReadOnlyList<string> headers,
        IReadOnlyList<IReadOnlyList<string>> rows)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(rows);

        if (headers.Count is 0 or > MaxColumns)
        {
            throw new ArgumentException(
                $"A sheet needs between 1 and {MaxColumns} columns.",
                nameof(headers));
        }

        using var buffer = new MemoryStream();

        // No compression level is set beyond the default: these files are a few hundred
        // kilobytes of text at most, and a smaller file is not worth a knob nobody will turn.
        using (var archive = new ZipArchive(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            Write(archive, "[Content_Types].xml", ContentTypes());
            Write(archive, "_rels/.rels", RootRelationships());
            Write(archive, "xl/workbook.xml", Workbook(SheetName(sheetName)));
            Write(archive, "xl/_rels/workbook.xml.rels", WorkbookRelationships());
            Write(archive, "xl/styles.xml", Styles());
            Write(archive, "xl/worksheets/sheet1.xml", Sheet(headers, rows));
        }

        return buffer.ToArray();
    }

    private static void Write(ZipArchive archive, string path, string content)
    {
        var entry = archive.CreateEntry(path);

        using var stream = entry.Open();

        // No byte order mark. Some readers treat one at the start of an XML part as content and
        // then fail to parse the declaration.
        using var writer = new StreamWriter(stream, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

        writer.Write(content);
    }

    private static string ContentTypes() =>
        """
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
          <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
          <Default Extension="xml" ContentType="application/xml"/>
          <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
          <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
          <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
        </Types>
        """;

    private static string RootRelationships() =>
        """
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
          <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
        </Relationships>
        """;

    private static string Workbook(string sheetName) =>
        $"""
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
                  xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
          <sheets><sheet name="{Escape(sheetName)}" sheetId="1" r:id="rId1"/></sheets>
        </workbook>
        """;

    private static string WorkbookRelationships() =>
        """
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
          <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
          <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
        </Relationships>
        """;

    /// <summary>
    /// Two cell formats: the body, and a bold header on a tinted fill.
    /// </summary>
    /// <remarks>
    /// The fonts, fills, borders and cellStyleXfs entries are all required by the schema even
    /// when they are empty. Omitting them is the usual cause of a file Excel offers to repair.
    /// </remarks>
    private static string Styles() =>
        """
        <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
          <fonts count="2">
            <font><sz val="11"/><name val="Calibri"/></font>
            <font><b/><sz val="11"/><color rgb="FF1F1F2E"/><name val="Calibri"/></font>
          </fonts>
          <fills count="3">
            <fill><patternFill patternType="none"/></fill>
            <fill><patternFill patternType="gray125"/></fill>
            <fill><patternFill patternType="solid"><fgColor rgb="FFEEF1FF"/><bgColor indexed="64"/></patternFill></fill>
          </fills>
          <borders count="2">
            <border><left/><right/><top/><bottom/><diagonal/></border>
            <border><left/><right/><top/><bottom style="thin"><color rgb="FFC7CFFF"/></bottom><diagonal/></border>
          </borders>
          <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
          <cellXfs count="2">
            <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1">
              <alignment vertical="top" wrapText="0"/>
            </xf>
            <xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1"/>
          </cellXfs>
        </styleSheet>
        """;

    private static string Sheet(
        IReadOnlyList<string> headers,
        IReadOnlyList<IReadOnlyList<string>> rows)
    {
        var width = headers.Count;
        var sheet = new StringBuilder(4096);

        sheet.Append("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>");
        sheet.Append("<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\">");

        sheet.Append("<sheetViews><sheetView workbookViewId=\"0\">");

        // The header stays put while the body scrolls, which is the one thing every reader of
        // an exported table does first.
        sheet.Append("<pane ySplit=\"1\" topLeftCell=\"A2\" activePane=\"bottomLeft\" state=\"frozen\"/>");
        sheet.Append("</sheetView></sheetViews>");

        sheet.Append("<cols>");

        for (var column = 0; column < width; column++)
        {
            var widest = headers[column]?.Length ?? 0;

            foreach (var row in rows)
            {
                if (column < row.Count)
                {
                    widest = Math.Max(widest, row[column]?.Length ?? 0);
                }
            }

            var chars = Math.Clamp(widest + 2, MinColumnWidth, MaxColumnWidth);

            sheet.Append(CultureInfo.InvariantCulture, $"<col min=\"{column + 1}\" max=\"{column + 1}\" width=\"{chars}\" customWidth=\"1\"/>");
        }

        sheet.Append("</cols><sheetData>");

        AppendRow(sheet, 1, headers, styleIndex: 1);

        for (var index = 0; index < rows.Count; index++)
        {
            AppendRow(sheet, index + 2, rows[index], styleIndex: 0, width);
        }

        sheet.Append("</sheetData>");

        // The filter arrows every reader expects on an exported table.
        sheet.Append(CultureInfo.InvariantCulture, $"<autoFilter ref=\"A1:{Reference(width, rows.Count + 1)}\"/>");
        sheet.Append("</worksheet>");

        return sheet.ToString();
    }

    private static void AppendRow(
        StringBuilder sheet,
        int rowNumber,
        IReadOnlyList<string> values,
        int styleIndex,
        int? width = null)
    {
        sheet.Append(CultureInfo.InvariantCulture, $"<row r=\"{rowNumber}\">");

        var count = width ?? values.Count;

        for (var column = 0; column < count; column++)
        {
            // A row shorter than the header is padded and a longer one is truncated, rather
            // than producing a sheet whose rows have different widths. A ragged sheet is a file
            // that opens and then misleads, which is worse than one that does not open.
            var value = column < values.Count ? values[column] : null;

            sheet.Append(CultureInfo.InvariantCulture, $"<c r=\"{Reference(column + 1, rowNumber)}\" s=\"{styleIndex}\" t=\"inlineStr\"><is><t xml:space=\"preserve\">");
            sheet.Append(Escape(value));
            sheet.Append("</t></is></c>");
        }

        sheet.Append("</row>");
    }

    /// <summary>Turns a one-based column and row into a cell reference such as <c>AB12</c>.</summary>
    private static string Reference(int column, int row)
    {
        var letters = new StringBuilder(3);

        for (var remaining = column; remaining > 0; remaining = (remaining - 1) / 26)
        {
            letters.Insert(0, (char)('A' + ((remaining - 1) % 26)));
        }

        return letters.Append(row.ToString(CultureInfo.InvariantCulture)).ToString();
    }

    /// <summary>
    /// Escapes a value for XML, and drops the characters XML 1.0 cannot carry at all.
    /// </summary>
    /// <remarks>
    /// A control character in the middle of a part makes the whole file unreadable, and these
    /// values come from names, user agents and addresses that something else chose. Dropping
    /// one character is a better outcome than a workbook that will not open.
    /// </remarks>
    private static string Escape(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var escaped = new StringBuilder(value.Length + 16);

        foreach (var character in value)
        {
            switch (character)
            {
                case '&': escaped.Append("&amp;"); break;
                case '<': escaped.Append("&lt;"); break;
                case '>': escaped.Append("&gt;"); break;
                case '"': escaped.Append("&quot;"); break;
                case '\'': escaped.Append("&apos;"); break;
                case '\t' or '\n' or '\r': escaped.Append(character); break;
                default:
                    if (character >= ' ' && character != '￾' && character != '￿')
                    {
                        escaped.Append(character);
                    }

                    break;
            }
        }

        return escaped.ToString();
    }

    /// <summary>
    /// Cleans a sheet name down to what Excel accepts.
    /// </summary>
    /// <remarks>
    /// Thirty-one characters, and none of <c>: \ / ? * [ ]</c>. A name breaking either rule is
    /// another cause of the repair prompt, and the name is the one part of this file that comes
    /// from a page rather than from this class.
    /// </remarks>
    private static string SheetName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return "Export";
        }

        var cleaned = new StringBuilder(31);

        foreach (var character in name.Trim())
        {
            if (cleaned.Length == 31)
            {
                break;
            }

            cleaned.Append(character is ':' or '\\' or '/' or '?' or '*' or '[' or ']' ? ' ' : character);
        }

        return cleaned.Length == 0 ? "Export" : cleaned.ToString();
    }
}
