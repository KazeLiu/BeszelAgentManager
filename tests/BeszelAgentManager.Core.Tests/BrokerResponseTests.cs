using BeszelAgentManager.Core;
using Xunit;

namespace BeszelAgentManager.Core.Tests;

public sealed class BrokerResponseTests
{
    [Fact]
    public void AcceptedUpdateIsNotReportedAsCompleted()
    {
        var accepted = BrokerResponse.Accepted("request");
        Assert.Equal("accepted", accepted.State);
        Assert.Equal("request", accepted.RequestId);
        Assert.Equal("accepted", accepted.Message);
        Assert.True(accepted.Success);
        Assert.Equal("completed", BrokerResponse.Completed("request").State);
    }
}
