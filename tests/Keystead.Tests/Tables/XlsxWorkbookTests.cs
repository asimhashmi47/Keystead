using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Xml.Linq;
using Keystead.Web.Tables;
using Xunit;

namespace Keystead.Tests.Tables;

/// <summary>
/// The workbook writer, checked as a file rather than as a string.
/// </summary>
/// <remarks>
/// A spreadsheet that Excel offers to repair is worse than no export at all: the person who
/// asked for one concludes the product is broken, and they are not wrong. Every test here opens
/// the produced bytes as a zip and parses the parts as XML, which is what a reader does, so a
/// malformed part fails here rather than on someone's desk.
/// </remarks>
public sealed class XlsxWorkbookTests
{
    private static readonly XNamespace Main =
        "http://schemas.openxmlformats.org/spreadsheetml/2006/main";

    private static ZipArchive Open(byte[] bytes) =>
        new(new MemoryStream(bytes), ZipArchiveMode.Read);

    private static XDocument Part(byte[] bytes, string path)
    {
        using var archive = Open(bytes);

        var entry = archive.GetEntry(path);
        Assert.NotNull(entry);

        using var stream = entry.Open();
        return XDocument.Load(stream);
    }

    private static byte[] Simple() => XlsxWorkbook.Create(
        "Members",
        ["Person", "Role"],
        [["Ada Lovelace", "Owner"], ["Grace Hopper", "Admin"]]);

    [Fact]
    public void TheFile_IsAZipWithEveryPartAReaderNeeds()
    {
        using var archive = Open(Simple());

        var names = archive.Entries.Select(e => e.FullName).ToList();

        Assert.Contains("[Content_Types].xml", names);
        Assert.Contains("_rels/.rels", names);
        Assert.Contains("xl/workbook.xml", names);
        Assert.Contains("xl/_rels/workbook.xml.rels", names);
        Assert.Contains("xl/styles.xml", names);
        Assert.Contains("xl/worksheets/sheet1.xml", names);
    }

    [Fact]
    public void EveryPart_IsWellFormedXml()
    {
        var bytes = Simple();

        using var archive = Open(bytes);

        foreach (var entry in archive.Entries)
        {
            using var stream = entry.Open();

            // Throws on malformed XML, which is the whole assertion.
            _ = XDocument.Load(stream);
        }
    }

    [Fact]
    public void NoPart_StartsWithAByteOrderMark()
    {
        // Some readers treat a mark before the XML declaration as content and then fail to
        // parse the declaration at all.
        using var archive = Open(Simple());

        foreach (var entry in archive.Entries)
        {
            using var stream = entry.Open();
            var first = new byte[3];
            var read = stream.ReadAtLeast(first, 3, throwOnEndOfStream: false);

            Assert.True(read < 3 || first is not [0xEF, 0xBB, 0xBF]);
        }
    }

    [Fact]
    public void TheHeaderAndTheRows_AreWhereTheyShouldBe()
    {
        var sheet = Part(Simple(), "xl/worksheets/sheet1.xml");

        var rows = sheet.Descendants(Main + "row").ToList();

        Assert.Equal(3, rows.Count);
        Assert.Equal("1", rows[0].Attribute("r")?.Value);

        var cells = rows[1].Descendants(Main + "t").Select(t => t.Value).ToList();

        Assert.Equal(["Ada Lovelace", "Owner"], cells);
    }

    [Fact]
    public void EveryCell_IsAnInlineStringRatherThanAFormula()
    {
        // The reason there is no formula injection to defend against here: a string cell is
        // displayed, never evaluated, whatever it begins with.
        var bytes = XlsxWorkbook.Create(
            "Audit",
            ["Detail"],
            [["=1+1"], ["+44 20 7946 0000"], ["@everyone"], ["-5"]]);

        var sheet = Part(bytes, "xl/worksheets/sheet1.xml");

        Assert.Empty(sheet.Descendants(Main + "f"));

        foreach (var cell in sheet.Descendants(Main + "c"))
        {
            Assert.Equal("inlineStr", cell.Attribute("t")?.Value);
        }

        var values = sheet.Descendants(Main + "t").Select(t => t.Value).ToList();

        Assert.Contains("=1+1", values);
        Assert.Contains("@everyone", values);
    }

    [Fact]
    public void MarkupInAValue_IsEscapedRatherThanEmbedded()
    {
        var bytes = XlsxWorkbook.Create(
            "Secrets",
            ["Name"],
            [["<script>alert('x')</script> & \"friends\""]]);

        var sheet = Part(bytes, "xl/worksheets/sheet1.xml");
        var value = sheet.Descendants(Main + "t").Last().Value;

        Assert.Equal("<script>alert('x')</script> & \"friends\"", value);
    }

    [Fact]
    public void AControlCharacter_IsDroppedRatherThanBreakingTheFile()
    {
        // These values come from names, user agents and addresses that something else chose.
        // One stray control character would otherwise make the whole part unreadable.
        var bytes = XlsxWorkbook.Create("Sheet", ["Value"], [["before\u0001\u0008after"]]);

        var sheet = Part(bytes, "xl/worksheets/sheet1.xml");

        Assert.Equal("beforeafter", sheet.Descendants(Main + "t").Last().Value);
    }

    [Fact]
    public void TabsAndNewlines_Survive()
    {
        var bytes = XlsxWorkbook.Create("Sheet", ["Value"], [["a\tb\nc"]]);

        var sheet = Part(bytes, "xl/worksheets/sheet1.xml");

        Assert.Contains('\t', sheet.Descendants(Main + "t").Last().Value);
    }

    [Fact]
    public void AShortRow_IsPaddedAndALongOneIsTruncated()
    {
        // A sheet whose rows have different widths opens and then misleads, which is worse
        // than one that does not open.
        var bytes = XlsxWorkbook.Create(
            "Sheet",
            ["A", "B", "C"],
            [["1"], ["1", "2", "3", "4"]]);

        var sheet = Part(bytes, "xl/worksheets/sheet1.xml");

        foreach (var row in sheet.Descendants(Main + "row"))
        {
            Assert.Equal(3, row.Descendants(Main + "c").Count());
        }
    }

    [Theory]
    [InlineData("Production: secrets", "Production  secrets")]
    [InlineData("a/b\\c?d*e[f]g", "a b c d e f g")]
    [InlineData("", "Export")]
    [InlineData("   ", "Export")]
    public void TheSheetName_IsCleanedToWhatExcelAccepts(string given, string expected)
    {
        var workbook = Part(XlsxWorkbook.Create(given, ["A"], []), "xl/workbook.xml");

        Assert.Equal(expected, workbook.Descendants(Main + "sheet").Single().Attribute("name")?.Value);
    }

    [Fact]
    public void AVeryLongSheetName_IsCutToThirtyOneCharacters()
    {
        var workbook = Part(
            XlsxWorkbook.Create(new string('x', 80), ["A"], []),
            "xl/workbook.xml");

        Assert.Equal(31, workbook.Descendants(Main + "sheet").Single().Attribute("name")?.Value?.Length);
    }

    [Fact]
    public void TheSheet_FreezesTheHeaderAndOffersFilters()
    {
        var sheet = Part(Simple(), "xl/worksheets/sheet1.xml");

        Assert.Equal("frozen", sheet.Descendants(Main + "pane").Single().Attribute("state")?.Value);
        Assert.Equal("A1:B3", sheet.Descendants(Main + "autoFilter").Single().Attribute("ref")?.Value);
    }

    [Fact]
    public void ColumnReferences_CarryOnPastZ()
    {
        // The twenty-seventh column is AA, not BA or [. Getting this wrong produces a file
        // that opens for small tables and fails for large ones.
        var headers = Enumerable.Range(1, 28).Select(i => $"H{i}").ToList();
        var sheet = Part(XlsxWorkbook.Create("Wide", headers, []), "xl/worksheets/sheet1.xml");

        var references = sheet.Descendants(Main + "c")
            .Select(c => c.Attribute("r")?.Value)
            .ToList();

        Assert.Contains("Z1", references);
        Assert.Contains("AA1", references);
        Assert.Contains("AB1", references);
    }

    [Fact]
    public void ASheetWithNoColumns_IsRefused()
    {
        Assert.Throws<ArgumentException>(() => XlsxWorkbook.Create("Sheet", [], []));
    }

    [Fact]
    public void ASheetWithNoRows_IsStillAValidWorkbook()
    {
        var sheet = Part(XlsxWorkbook.Create("Empty", ["A", "B"], []), "xl/worksheets/sheet1.xml");

        Assert.Single(sheet.Descendants(Main + "row"));
    }

    [Fact]
    public void AValueWithAnAccent_SurvivesTheRoundTrip()
    {
        var bytes = XlsxWorkbook.Create("Sheet", ["Name"], [["Ada Lovelace — Zürich"]]);

        var sheet = Part(bytes, "xl/worksheets/sheet1.xml");

        Assert.Equal("Ada Lovelace — Zürich", sheet.Descendants(Main + "t").Last().Value);
    }

    [Fact]
    public void TheContentTypes_NameEveryPart()
    {
        var types = Part(Simple(), "[Content_Types].xml").ToString();

        Assert.Contains("/xl/workbook.xml", types, StringComparison.Ordinal);
        Assert.Contains("/xl/worksheets/sheet1.xml", types, StringComparison.Ordinal);
        Assert.Contains("/xl/styles.xml", types, StringComparison.Ordinal);
    }

    [Fact]
    public void TheDeclaredMediaType_IsTheOneExcelExpects()
    {
        Assert.Equal(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            XlsxWorkbook.ContentType);
    }

    [Fact]
    public void AWideTable_StillProducesOneCellPerColumnPerRow()
    {
        var headers = Enumerable.Range(1, 40).Select(i => $"H{i}").ToList();

        var rows = Enumerable.Range(1, 50)
            .Select(r => (IReadOnlyList<string>)[.. Enumerable.Range(1, 40).Select(c => $"r{r}c{c}")])
            .ToList();

        var sheet = Part(XlsxWorkbook.Create("Big", headers, rows), "xl/worksheets/sheet1.xml");

        Assert.Equal(51, sheet.Descendants(Main + "row").Count());
        Assert.Equal(51 * 40, sheet.Descendants(Main + "c").Count());
    }

    [Fact]
    public void TheBytes_AreSelfContained()
    {
        // No temporary file, no stream the caller has to keep open: a handler returns these
        // bytes directly, and a writer that depended on a disposed stream would fail only
        // under load.
        var bytes = Simple();

        Assert.True(bytes.Length > 1_000);
        Assert.Equal(Encoding.ASCII.GetBytes("PK"), bytes[..2]);
    }
}
