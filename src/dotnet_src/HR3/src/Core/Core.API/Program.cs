using Core.API.Endpoints;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();



app.MapGet("/", () => "Hello World!");

app.MapPost("/identity", () =>  IdentityEndpoint.Authenticate);


app.Run();