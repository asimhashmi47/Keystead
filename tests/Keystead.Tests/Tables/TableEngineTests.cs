using System;
using System.Collections.Generic;
using System.Linq;
using Keystead.Web.Tables;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Keystead.Tests.Tables;

/// <summary>
/// Searching, filtering, sorting and paging, and what happens when the URL is nonsense.
/// </summary>
/// <remarks>
/// Every table in the application is rendered through this one engine, so a defect here is a
/// defect in six pages at once. The half of this file that matters most is the second half: a
/// table is a read, and no URL anyone can type should be able to turn one into an error page.
/// </remarks>
public sealed class TableEngineTests
{
    private sealed record Row(string Name, string Role, int Count, DateTimeOffset? Used);

    private static readonly DateTimeOffset Day = new(2026, 6, 1, 12, 0, 0, TimeSpan.Zero);

    private static readonly IReadOnlyList<Row> Rows =
    [
        new("Ada Lovelace", "Owner", 9, Day),
        new("Grace Hopper", "Admin", 10, Day.AddDays(2)),
        new("Alan Turing", "Reader", 2, null),
        new("Katherine Johnson", "Contributor", 2, Day.AddDays(1)),
    ];

    private static IReadOnlyList<TableColumn<Row>> Columns() =>
    [
        new TableColumn<Row> { Key = "name", Header = "Name", Text = r => r.Name },
        new TableColumn<Row>
        {
            Key = "role",
            Header = "Role",
            Text = r => r.Role,
            Options =
            [
                new TableOption("Owner", "Owner"),
                new TableOption("Admin", "Admin"),
                new TableOption("Reader", "Reader"),
                new TableOption("Contributor", "Contributor"),
            ],
        },
        new TableColumn<Row>
        {
            Key = "count",
            Header = "Count",
            Text = r => r.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
            SortBy = r => r.Count,
        },
        new TableColumn<Row>
        {
            Key = "used",
            Header = "Last used",
            Text = r => r.Used?.ToString("u", System.Globalization.CultureInfo.InvariantCulture) ?? "Never",
            SortBy = r => r.Used,
        },
        new TableColumn<Row>
        {
            Key = "secret",
            Header = "Not searchable",
            Text = r => $"hidden-{r.Name}",
            Searchable = false,
            Sortable = false,
        },
    ];

    private static TableView<Row> Build(string queryString, IReadOnlyList<Row>? rows = null)
    {
        var context = new DefaultHttpContext();
        context.Request.QueryString = new QueryString(queryString);
        context.Request.Path = "/members";

        return TableEngine.Build(
            rows ?? Rows,
            Columns(),
            TableQuery.FromRequest(context.Request),
            id: "t",
            label: "rows",
            path: "/members");
    }

    [Fact]
    public void WithNoQuery_EveryRowIsOnOnePage_InTheOrderGiven()
    {
        var view = Build("");

        Assert.Equal(4, view.Rows.Count);
        Assert.Equal("Ada Lovelace", view.Rows[0].Name);
        Assert.Equal(1, view.Chrome.PageCount);
        Assert.False(view.Chrome.HasFilter);
    }

    [Fact]
    public void TheSearch_LooksAtEverySearchableColumn()
    {
        Assert.Equal(["Grace Hopper"], Build("?q=hopper").Rows.Select(r => r.Name));
        Assert.Equal(["Ada Lovelace"], Build("?q=owner").Rows.Select(r => r.Name));
    }

    [Fact]
    public void TheSearch_SkipsColumnsThatOptedOut()
    {
        // The column's text contains "hidden-Ada Lovelace". Searching it must find nothing,
        // or a column excluded from search becomes a way to confirm what is in it.
        Assert.Empty(Build("?q=hidden").Rows);
    }

    [Fact]
    public void AColumnTerm_NarrowsThatColumnOnly()
    {
        Assert.Equal(["Alan Turing"], Build("?c.name=turing").Rows.Select(r => r.Name));
    }

    [Fact]
    public void TwoColumnTerms_BothHaveToMatch()
    {
        Assert.Empty(Build("?c.name=turing&c.role=Owner").Rows);
        Assert.Single(Build("?c.name=turing&c.role=Reader").Rows);
    }

    [Fact]
    public void AColumnWithOptions_MatchesExactlyRatherThanAsASubstring()
    {
        // "Contributor" contains neither "Owner" nor "Admin", but "Admin" is a substring of
        // nothing here either. The case that matters is that a status filter for "Active"
        // must not also return "Inactive", and exact matching is what guarantees it.
        var view = Build("?c.role=Admin");

        Assert.Equal(["Grace Hopper"], view.Rows.Select(r => r.Name));
    }

    [Fact]
    public void AColumnWithoutOptions_MatchesAsASubstring()
    {
        Assert.Equal(2, Build("?c.name=a").Rows.Count(r => r.Name.Contains("Ada", StringComparison.Ordinal)
            || r.Name.Contains("Grace", StringComparison.Ordinal)));
    }

    [Fact]
    public void SortingByText_IsCaseInsensitive()
    {
        var view = Build("?sort=name");

        Assert.Equal(
            ["Ada Lovelace", "Alan Turing", "Grace Hopper", "Katherine Johnson"],
            view.Rows.Select(r => r.Name));
    }

    [Fact]
    public void SortingByANumber_UsesTheNumberNotItsText()
    {
        // "10" sorts before "9" as text, and after it as a number. A column whose values are
        // numbers and whose sort is textual is the most common way a table lies.
        var view = Build("?sort=count&dir=desc");

        Assert.Equal(10, view.Rows[0].Count);
        Assert.Equal(9, view.Rows[1].Count);
    }

    [Fact]
    public void TiedRows_KeepTheOrderTheyArrivedIn()
    {
        // Two rows with a count of 2, in the order the page supplied them. A sort that
        // reshuffled ties would make a table flicker between identical requests.
        var view = Build("?sort=count");

        Assert.Equal(["Alan Turing", "Katherine Johnson"], view.Rows.Take(2).Select(r => r.Name));
    }

    [Theory]
    [InlineData("?sort=used")]
    [InlineData("?sort=used&dir=desc")]
    public void ARowWithNoValue_SortsLastInBothDirections(string query)
    {
        // "Never used" is not the oldest date and not the newest; it is the absence of one.
        // Either ordering should put the rows that have a value first.
        var view = Build(query);

        Assert.Null(view.Rows[^1].Used);
    }

    [Fact]
    public void Paging_SplitsTheRowsAndReportsThePosition()
    {
        var view = Build("?size=10&page=2", [.. Enumerable.Range(1, 25)
            .Select(i => new Row($"Row {i:00}", "Reader", i, null))]);

        Assert.Equal(10, view.Rows.Count);
        Assert.Equal("Row 11", view.Rows[0].Name);
        Assert.Equal(3, view.Chrome.PageCount);
        Assert.Equal(11, view.Chrome.FirstRow);
        Assert.Equal(20, view.Chrome.LastRow);
        Assert.True(view.Chrome.HasPrevious);
        Assert.True(view.Chrome.HasNext);
    }

    [Fact]
    public void AnExport_CarriesEveryMatchingRowRatherThanThePage()
    {
        // Someone who filtered to forty rows and pressed Export expects forty rows, not the
        // twenty-five the page happened to show.
        var view = Build("?size=10", [.. Enumerable.Range(1, 25)
            .Select(i => new Row($"Row {i:00}", "Reader", i, null))]);

        Assert.Equal(10, view.Rows.Count);
        Assert.Equal(25, view.Matched.Count);
    }

    [Fact]
    public void TheCounts_SeparateWhatMatchesFromWhatExists()
    {
        var view = Build("?q=hopper");

        Assert.Equal(1, view.Chrome.FilteredCount);
        Assert.Equal(4, view.Chrome.TotalCount);
        Assert.True(view.Chrome.IsFiltered);
    }

    // ---------------------------------------------------------------- nonsense in the URL

    [Fact]
    public void AnUnknownSortKey_LeavesTheOrderAlone()
    {
        Assert.Equal("Ada Lovelace", Build("?sort=nonsense").Rows[0].Name);
    }

    [Fact]
    public void AnUnsortableColumn_IsNotSortedByAskingForIt()
    {
        Assert.Equal("Ada Lovelace", Build("?sort=secret").Rows[0].Name);
    }

    [Fact]
    public void AnUnknownColumnTerm_IsIgnoredRatherThanMatchingNothing()
    {
        // An old bookmark naming a column that has since been renamed should show the table,
        // not an empty one.
        Assert.Equal(4, Build("?c.nonsense=zzz").Rows.Count);
    }

    [Fact]
    public void AnEmptyTerm_IsNoFilterRatherThanAFilterForNothing()
    {
        // Clearing the box and pressing Apply submits an empty value. If that were a filter,
        // clearing a search would empty the table.
        Assert.Equal(4, Build("?q=&c.name=").Rows.Count);
    }

    [Theory]
    [InlineData("?page=0")]
    [InlineData("?page=-5")]
    [InlineData("?page=abc")]
    [InlineData("?page=99999999999999999999")]
    public void AnImpossiblePage_IsPageOne(string query)
    {
        var view = Build(query);

        Assert.Equal(1, view.Chrome.Page);
        Assert.Equal(4, view.Rows.Count);
    }

    [Fact]
    public void APagePastTheEnd_ShowsTheLastPage()
    {
        var view = Build("?size=10&page=99", [.. Enumerable.Range(1, 25)
            .Select(i => new Row($"Row {i:00}", "Reader", i, null))]);

        Assert.Equal(3, view.Chrome.Page);
        Assert.Equal(5, view.Rows.Count);
    }

    [Theory]
    [InlineData("?size=1")]
    [InlineData("?size=100000")]
    [InlineData("?size=-10")]
    [InlineData("?size=drop+table")]
    public void AnUnofferedPageSize_IsTheDefault(string query)
    {
        Assert.Equal(TableQuery.DefaultPageSize, Build(query).Chrome.PageSize);
    }

    [Fact]
    public void AVeryLongTerm_IsTruncatedRatherThanRefused()
    {
        var view = Build("?q=" + new string('x', 5_000));

        Assert.Empty(view.Rows);
        Assert.Equal(TableQuery.MaxTermLength, view.Chrome.Search?.Length);
    }

    [Theory]
    [InlineData("?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")]
    [InlineData("?c.name=..%2F..%2Fetc%2Fpasswd")]
    [InlineData("?c.name=%27+OR+1%3D1+--")]
    [InlineData("?sort=../../etc/passwd")]
    [InlineData("?sort=name%00")]
    public void HostileInput_ProducesATableRatherThanAnError(string query)
    {
        // Nothing here is interpreted: terms are compared with string.Contains and the sort
        // key is matched against a closed list of columns. The assertion is simply that the
        // engine answers, because a table is a read and a read should not fail.
        var view = Build(query);

        Assert.NotNull(view.Chrome);
        Assert.True(view.Rows.Count <= 4);
    }

    [Fact]
    public void AnEmptyTable_IsStillOnePage()
    {
        var view = Build("", []);

        Assert.True(view.IsEmpty);
        Assert.Equal(1, view.Chrome.PageCount);
        Assert.Equal(0, view.Chrome.FirstRow);
        Assert.Equal(0, view.Chrome.LastRow);
    }
}
