using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Xml.Linq;
using Keystead.Web.Tables;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Keystead.Tests.Tables;

/// <summary>
/// What a download contains, and what it must not.
/// </summary>
public sealed class TableExportTests
{
    private static readonly XNamespace Main =
        "http://schemas.openxmlformats.org/spreadsheetml/2006/main";

    private sealed record Row(string Name, string Status, string Internal);

    private static readonly IReadOnlyList<Row> Rows =
    [
        new("Stripe--SecretKey", "Active", "never-exported"),
        new("Redis--ConnectionString", "Expiring soon", "never-exported"),
        new("Jwt--SigningKey", "Expired", "never-exported"),
    ];

    private static TableView<Row> Build(string queryString = "")
    {
        var context = new DefaultHttpContext();
        context.Request.QueryString = new QueryString(queryString);

        return TableEngine.Build(
            Rows,
            [
                new TableColumn<Row> { Key = "name", Header = "Name", Text = r => r.Name },
                new TableColumn<Row> { Key = "status", Header = "Status", Text = r => r.Status },
                new TableColumn<Row>
                {
                    Key = "actions",
                    Header = "Actions",
                    Text = r => r.Internal,
                    Exported = false,
                },
            ],
            TableQuery.FromRequest(context.Request),
            id: "t",
            label: "secrets",
            path: "/vaults/production");
    }

    private static string CsvOf(TableView<Row> view)
    {
        var file = TableExport.ToFile(view, TableExportFormat.Csv, "Secrets");

        return Encoding.UTF8.GetString(file.FileContents);
    }

    private static IReadOnlyList<string> SheetValues(TableView<Row> view)
    {
        var file = TableExport.ToFile(view, TableExportFormat.Excel, "Secrets");

        using var archive = new ZipArchive(new MemoryStream(file.FileContents), ZipArchiveMode.Read);
        using var stream = archive.GetEntry("xl/worksheets/sheet1.xml")!.Open();

        return [.. XDocument.Load(stream).Descendants(Main + "t").Select(t => t.Value)];
    }

    [Fact]
    public void AColumnThatOptedOut_IsNotInTheFile()
    {
        // An actions column is a row of buttons, not a value. The point of the flag is that a
        // column can be on screen without being in a file.
        Assert.DoesNotContain("never-exported", CsvOf(Build()), StringComparison.Ordinal);
        Assert.DoesNotContain("never-exported", SheetValues(Build()));
    }

    [Fact]
    public void TheFile_HoldsWhatTheFilterMatched()
    {
        var values = SheetValues(Build("?c.status=Expired"));

        Assert.Contains("Jwt--SigningKey", values);
        Assert.DoesNotContain("Stripe--SecretKey", values);
    }

    [Fact]
    public void TheFile_IsInTheSortTheScreenWasIn()
    {
        var values = SheetValues(Build("?sort=name"));
        var names = values.Where(v => v.Contains("--", StringComparison.Ordinal)).ToList();

        Assert.Equal(["Jwt--SigningKey", "Redis--ConnectionString", "Stripe--SecretKey"], names);
    }

    [Fact]
    public void TheFile_IgnoresThePageTheScreenWasOn()
    {
        var values = SheetValues(Build("?size=10&page=1"));

        Assert.Contains("Stripe--SecretKey", values);
        Assert.Contains("Redis--ConnectionString", values);
        Assert.Contains("Jwt--SigningKey", values);
    }

    [Fact]
    public void TheCsv_DefusesAFieldThatASpreadsheetWouldTreatAsAFormula()
    {
        var context = new DefaultHttpContext();

        var view = TableEngine.Build(
            [new Row("=HYPERLINK(\"http://evil\",\"click\")", "Active", "x")],
            [new TableColumn<Row> { Key = "name", Header = "Name", Text = r => r.Name }],
            TableQuery.FromRequest(context.Request),
            id: "t",
            label: "rows",
            path: "/");

        var csv = CsvOf(view);

        Assert.Contains("\"'=HYPERLINK", csv, StringComparison.Ordinal);
    }

    [Fact]
    public void TheCsv_QuotesAndDoublesQuotes()
    {
        var context = new DefaultHttpContext();

        var view = TableEngine.Build(
            [new Row("a \"quoted\", comma", "Active", "x")],
            [new TableColumn<Row> { Key = "name", Header = "Name", Text = r => r.Name }],
            TableQuery.FromRequest(context.Request),
            id: "t",
            label: "rows",
            path: "/");

        Assert.Contains("\"a \"\"quoted\"\", comma\"", CsvOf(view), StringComparison.Ordinal);
    }

    [Fact]
    public void TheCsv_CarriesAByteOrderMarkSoExcelReadsItAsUnicode()
    {
        var file = TableExport.ToFile(Build(), TableExportFormat.Csv, "Secrets");

        Assert.Equal<byte[]>([0xEF, 0xBB, 0xBF], file.FileContents[..3]);
    }

    [Theory]
    [InlineData("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".xlsx")]
    [InlineData("csv", "text/csv; charset=utf-8", ".csv")]
    [InlineData(null, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".xlsx")]
    [InlineData("nonsense", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".xlsx")]
    public void TheFormat_IsReadFromTheQueryAndDefaultsToAWorkbook(
        string? format,
        string expectedType,
        string expectedExtension)
    {
        var file = TableExport.ToFile(Build(), TableExport.ParseFormat(format), "Secrets");

        Assert.Equal(expectedType, file.ContentType);
        Assert.EndsWith(expectedExtension, file.FileDownloadName, StringComparison.Ordinal);
    }

    [Fact]
    public void TheFileName_IsSafeAndSaysWhenItWasTaken()
    {
        var file = TableExport.ToFile(Build(), TableExportFormat.Excel, "Production secrets");

        Assert.StartsWith("keystead-production-secrets-", file.FileDownloadName, StringComparison.Ordinal);
        Assert.DoesNotContain(' ', file.FileDownloadName);
    }

    [Fact]
    public void AVeryLargeTable_IsCappedRatherThanStreamedWithoutLimit()
    {
        var context = new DefaultHttpContext();
        context.Request.QueryString = new QueryString("?size=100");

        var many = Enumerable.Range(1, TableExport.MaxRows + 500)
            .Select(i => new Row($"Secret {i}", "Active", "x"))
            .ToList();

        var view = TableEngine.Build(
            many,
            [new TableColumn<Row> { Key = "name", Header = "Name", Text = r => r.Name }],
            TableQuery.FromRequest(context.Request),
            id: "t",
            label: "rows",
            path: "/");

        var file = TableExport.ToFile(view, TableExportFormat.Csv, "Secrets");
        var lines = Encoding.UTF8.GetString(file.FileContents).Split('\n', StringSplitOptions.RemoveEmptyEntries);

        // One header line plus the ceiling.
        Assert.Equal(TableExport.MaxRows + 1, lines.Length);
    }
}
