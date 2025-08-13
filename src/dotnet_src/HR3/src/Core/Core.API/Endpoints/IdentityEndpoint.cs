using Microsoft.AspNetCore.Http.HttpResults;

namespace Core.API.Endpoints;

public class IdentityEndpoint
{
    public static async Task<IResult> Authenticate(string username, string password)
    {
        
        return Results.Ok(1);
    }
}