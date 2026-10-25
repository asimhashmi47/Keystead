using System;
using System.Collections.Generic;
using Keystead.Web.Tables;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Keystead.Tests.Tables;

/// <summary>
/// The links a table builds: sorts, pages, chips and exports.
/// </summary>
/// <remarks>
/// These are the quiet failures. A sort link that drops the filter, or a page link that forgets
/// which vault you were looking at, produces a table that is simply wrong rather than one that
/// is broken, and nobody files a bug for it.
/// </remarks>
public sealed class TableLinkTests
{
    private sealed record Row(string Name);

    private static TableView<Row> Build(
        string queryString,
        IReadOnlyDictionary<string, string?>? preserved = null)
    {
        var context = new DefaultHttpContext();
        context.Request.QueryString = new QueryString(queryString);

        return TableEngine.Build(
            [new Row("one"), new Row("two")],
            [
                new TableColumn<Row> { Key = "name", Header = "Name", Text = r => r.Name },
                new TableColumn<Row> { Key = "other", Header = "Other", Text = _ => "x" },
            ],
            TableQuery.FromRequest(context.Request),
            id: "t",
            label: "rows",
            path: "/vaults/production",
            preserved: preserved);
    }

    [Fact]
    public void ASortLink_KeepsTheSearchAndTheFilters()
    {
        var url = Build("?q=prod&c.other=x").Chrome.Columns[0].SortUrl;

        Assert.Contains("q=prod", url, StringComparison.Ordinal);
        Assert.Contains("c.other=x", url, StringComparison.Ordinal);
        Assert.Contains("sort=name", url, StringComparison.Ordinal);
    }

    [Fact]
    public void ASortLink_ReturnsToTheFirstPage()
    {
        // Staying on page nine of a different order shows a page nobody asked for.
        var url = Build("?page=9").Chrome.Columns[0].SortUrl;

        Assert.DoesNotContain("page=", url, StringComparison.Ordinal);
    }

    [Fact]
    public void ClickingTheCurrentSortColumn_ReversesIt()
    {
        var ascending = Build("?sort=name&dir=asc").Chrome.Columns[0];
        var descending = Build("?sort=name&dir=desc").Chrome.Columns[0];

        Assert.Equal(TableSortState.Ascending, ascending.Sort);
        Assert.Contains("dir=desc", ascending.SortUrl, StringComparison.Ordinal);

        Assert.Equal(TableSortState.Descending, descending.Sort);
        Assert.Contains("dir=asc", descending.SortUrl, StringComparison.Ordinal);
    }

    [Fact]
    public void ClickingAnotherColumn_SortsItAscending()
    {
        var other = Build("?sort=name&dir=desc").Chrome.Columns[1];

        Assert.Equal(TableSortState.None, other.Sort);
        Assert.Contains("sort=other", other.SortUrl, StringComparison.Ordinal);
        Assert.Contains("dir=asc", other.SortUrl, StringComparison.Ordinal);
    }

    [Fact]
    public void APageLink_KeepsTheSearchTheFiltersAndTheSort()
    {
        var url = Build("?q=prod&c.other=x&sort=name&dir=desc").Chrome.PageUrl(2);

        Assert.Contains("q=prod", url, StringComparison.Ordinal);
        Assert.Contains("c.other=x", url, StringComparison.Ordinal);
        Assert.Contains("sort=name", url, StringComparison.Ordinal);
        Assert.Contains("dir=desc", url, StringComparison.Ordinal);
        Assert.Contains("page=2", url, StringComparison.Ordinal);
    }

    [Fact]
    public void RemovingOneFilter_LeavesTheOthers()
    {
        var url = Build("?q=prod&c.name=a&c.other=b").Chrome.WithoutColumn("name");

        Assert.DoesNotContain("c.name=", url, StringComparison.Ordinal);
        Assert.Contains("c.other=b", url, StringComparison.Ordinal);
        Assert.Contains("q=prod", url, StringComparison.Ordinal);
    }

    [Fact]
    public void ClearingEverything_KeepsWhatTheTableDoesNotOwn()
    {
        // The page's own state - which vault, whether deleted rows are shown - is not part of
        // the search, so clearing the search must not clear it.
        var preserved = new Dictionary<string, string?>(StringComparer.Ordinal) { ["deleted"] = "true" };
        var url = Build("?q=prod&c.name=a", preserved).Chrome.ClearUrl;

        Assert.DoesNotContain("q=", url, StringComparison.Ordinal);
        Assert.DoesNotContain("c.name=", url, StringComparison.Ordinal);
        Assert.Contains("deleted=true", url, StringComparison.Ordinal);
    }

    [Fact]
    public void TheExportLink_CarriesTheQueryAndNamesTheFormat()
    {
        var url = Build("?q=prod&sort=name").Chrome.ExportUrl("Export", "xlsx");

        Assert.Contains("handler=Export", url, StringComparison.Ordinal);
        Assert.Contains("format=xlsx", url, StringComparison.Ordinal);
        Assert.Contains("q=prod", url, StringComparison.Ordinal);
    }

    [Fact]
    public void TheExportLink_DoesNotCarryThePage()
    {
        // An export is the whole filtered set, so a page number in its URL would be a lie
        // about what the file contains.
        var url = Build("?page=4").Chrome.ExportUrl("Export", "csv");

        Assert.DoesNotContain("page=", url, StringComparison.Ordinal);
    }

    [Fact]
    public void EveryLink_IsEncoded()
    {
        // The values come from a query string someone can write. They are encoded on the way
        // back out, which is also why the URLs are built in one place rather than concatenated
        // at each call site.
        var url = Build("?q=a%20b%26c%3Dd").Chrome.PageUrl(2);

        Assert.DoesNotContain("a b&c=d", url, StringComparison.Ordinal);
        Assert.Contains("q=a%20b%26c%3Dd", url, StringComparison.Ordinal);
    }

    [Fact]
    public void ASelectionLink_KeepsTheViewItWasChosenFrom()
    {
        var url = Build("?q=prod&page=2&sort=name").Chrome.WithValue("member", "abc");

        Assert.Contains("member=abc", url, StringComparison.Ordinal);
        Assert.Contains("page=2", url, StringComparison.Ordinal);
        Assert.Contains("q=prod", url, StringComparison.Ordinal);
    }

    [Fact]
    public void TheFilterRow_OpensItselfWhenAColumnIsFiltered()
    {
        // Hiding an active filter is how someone concludes the table is broken.
        Assert.True(Build("?c.name=a").Chrome.FiltersOpen);
        Assert.False(Build("?q=a").Chrome.FiltersOpen);
        Assert.True(Build("?filters=1").Chrome.FiltersOpen);
    }

    [Fact]
    public void TheFilterRow_CannotBeClosedWhileAFilterIsInIt()
    {
        Assert.False(Build("?c.name=a").Chrome.CanCloseFilters);
        Assert.True(Build("?filters=1").Chrome.CanCloseFilters);
    }
}
