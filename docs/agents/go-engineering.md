# Go engineering

Validate untrusted data at the boundary. Use concrete types everywhere else.

Remove code that makes behavior harder to trace without solving a real problem. Replacing it with a framework, generic helper, or another layer is not a cleanup.

Apply these rules when changing Go code. Audit beyond the change only when requested. Follow the validation policy in [workflow.md](workflow.md), with commands defined in [Justfile](../../Justfile) and the [CI workflow](../../.github/workflows/ci.yml).

Use the upstream Kubernetes and Agent Sandbox types for their resources.

---

## 1. Remove unnecessary `any` and `interface{}`

Search for:

```go
any
interface{}
map[string]any
map[string]interface{}
```

Ask why the value is untyped.

Bad:

```go
func getDomain(data map[string]any) string {
    value, ok := data["domain"]
    if !ok {
        return ""
    }

    domain, ok := value.(string)
    if !ok {
        return ""
    }

    return domain
}
```

Prefer:

```go
type DomainEvent struct {
    Domain string `json:"domain"`
}
```

Then:

```go
event.Domain
```

Decode known JSON shapes into structs. Pass those structs downstream instead of recovering field types from maps at each call.

---

## 2. Stop creating generic conversion helpers

Be suspicious of functions like:

```go
toString()
asString()
stringValue()
safeString()
toInt()
asInt()
toBool()
toMap()
asMap()
getString()
getOptionalString()
valueOrDefault()
```

Bad:

```go
func toString(value any) string {
    switch v := value.(type) {
    case string:
        return v
    case int:
        return strconv.Itoa(v)
    case int64:
        return strconv.FormatInt(v, 10)
    case fmt.Stringer:
        return v.String()
    case nil:
        return ""
    default:
        return fmt.Sprintf("%v", v)
    }
}
```

Use the type the caller is supposed to supply. For a string:

```go
func normalizeDomain(domain string) string {
    return strings.ToLower(strings.TrimSpace(domain))
}
```

Accept `any` only when the function must handle different types.

---

## 3. Remove fallback-to-zero-value programming

Search for code that silently converts invalid states into:

```go
""
0
false
nil
[]T{}
map[K]V{}
```

Examples:

```go
if value == nil {
    return ""
}
```

```go
if err != nil {
    return nil
}
```

```go
if project == nil {
    return &Project{}
}
```

Return an error when required data is missing.

Bad:

```go
func projectID(project *Project) string {
    if project == nil {
        return ""
    }

    return project.ID
}
```

Prefer fixing the caller so `project` cannot be nil there.

If absence is part of the contract, handle it:

```go
if project == nil {
    return ErrProjectNotFound
}
```

Validate once before passing the value to callers that require it.

---

## 4. Do not add nil checks everywhere

Keep a nil check when nil is a valid input or can arrive from an external source.

Bad:

```go
func handleProject(project *Project) error {
    if project == nil {
        return errors.New("project is nil")
    }

    if project.Config == nil {
        return errors.New("project config is nil")
    }

    if project.Config.Domain == nil {
        return errors.New("domain is nil")
    }

    // actual logic
}
```

If those fields are required by the application model, redesign the types instead.

Prefer:

```go
type Project struct {
    Config ProjectConfig
}

type ProjectConfig struct {
    Domain string
}
```

Then:

```go
project.Config.Domain
```

Use value fields for required data unless pointer identity or shared mutation is needed.

---

## 5. Stop using pointers for everything

Review struct fields like:

```go
*string
*bool
*int
*time.Time
```

Use a pointer to distinguish missing data from a zero value only when callers need that distinction.

Bad:

```go
type Config struct {
    Enabled *bool
    Port    *int
    Name    *string
}
```

If those values are required:

```go
type Config struct {
    Enabled bool
    Port    int
    Name    string
}
```

Keep pointers for optional values, object identity, or shared mutation.

---

## 6. Remove pointless helper extraction

Check small helpers such as:

```go
getDomainID()
extractProjectID()
resolveName()
buildKey()
parseValue()
stringFrom()
domainFrom()
```

when the helper:

- has one caller
- only accesses a field
- only checks nil
- only calls `strings.TrimSpace`
- only calls `.String()`
- only performs a type assertion
- only forwards arguments

Bad:

```go
func domainIDFrom(record *DNSRecord) string {
    if record == nil {
        return ""
    }

    return record.DomainID.String()
}
```

Prefer:

```go
record.DomainID.String()
```

provided `record` is already known to exist.

Keep a helper when it names a domain operation or removes repeated logic.

---

## 7. Do not introduce interfaces without a real reason

Define interfaces at the consumer, with only the methods it needs. Check broad interfaces such as:

```go
type ProjectService interface {
    CreateProject(...)
    GetProject(...)
    UpdateProject(...)
    DeleteProject(...)
    ListProjects(...)
    ValidateProject(...)
    SyncProject(...)
    RefreshProject(...)
}
```

Use a concrete type unless an interface supports one of these needs:

- multiple implementations
- substitution
- testing at that boundary
- plugin behavior
- a narrow consumer contract

Bad:

```go
type DomainManager interface {
    Map(...)
}
```

with only:

```go
type domainManagerImpl struct{}
```

Prefer:

```go
type DomainManager struct{}
```

A concrete type does not need a matching `IFoo` or `FooImpl` pair.

---

## 8. Keep interfaces small

When an interface is justified, define only what the consumer needs.

Bad:

```go
type Repository interface {
    Create(...)
    Update(...)
    Delete(...)
    Get(...)
    List(...)
    Count(...)
    Exists(...)
    Search(...)
}
```

when a component only needs:

```go
Get(...)
```

Prefer:

```go
type projectGetter interface {
    Get(ctx context.Context, id string) (*Project, error)
}
```

Do not expose giant interfaces just because a concrete repository has many methods.

---

## 9. Remove unnecessary abstraction layers

Look for chains like:

```txt
handler
↓
controller
↓
service
↓
manager
↓
processor
↓
repository
↓
store
↓
database client
```

where most layers simply forward arguments.

Bad:

```go
func (s *Service) GetProject(ctx context.Context, id string) (*Project, error) {
    return s.manager.GetProject(ctx, id)
}
```

and:

```go
func (m *Manager) GetProject(ctx context.Context, id string) (*Project, error) {
    return m.repository.GetProject(ctx, id)
}
```

Remove layers that only forward calls. Keep those that enforce rules or hide implementation details the caller should not need.

---

## 10. Remove pass-through wrappers

Search for functions whose entire body is:

```go
return dependency.Do(...)
```

or:

```go
return helper(value)
```

or:

```go
result, err := dependency.Do(...)
if err != nil {
    return nil, err
}
return result, nil
```

Simplify:

```go
return dependency.Do(...)
```

Do not add wrappers purely to make the architecture look layered.

---

## 11. Simplify redundant error handling

Bad:

```go
result, err := repo.Get(ctx, id)
if err != nil {
    return nil, err
}

return result, nil
```

Prefer:

```go
return repo.Get(ctx, id)
```

Bad:

```go
if err != nil {
    return fmt.Errorf("error: %w", err)
}
```

This adds no useful context.

Include the operation and resource when wrapping:

```go
if err != nil {
    return fmt.Errorf("load project %s: %w", id, err)
}
```

Repeated wrapping can bury the cause:

```txt
failed to process project:
failed to get project:
failed to retrieve project:
failed to query project:
sql: no rows
```

Wrap an error when the added context identifies the failed operation or resource.

---

## 12. Do not swallow errors

Find:

```go
if err != nil {
    return nil
}
```

or:

```go
if err != nil {
    log.Println(err)
    return nil
}
```

or:

```go
_ = doSomething()
```

Propagate failures unless the operation can succeed without the failed step. Explain why an ignored error is safe.

Example:

```go
if err := cache.Delete(ctx, key); err != nil {
    logger.Warn("failed to invalidate cache", "key", key, "error", err)
}
```

Use this only when cache invalidation failure should not fail the operation.

---

## 13. Avoid unnecessary custom error types

Check whether callers distinguish error types such as:

```go
type ValidationError struct{}
type RepositoryError struct{}
type ServiceError struct{}
type DomainError struct{}
type InternalError struct{}
```

If callers handle them the same way, the separate types add no value.

Prefer:

```go
var ErrProjectNotFound = errors.New("project not found")
```

and:

```go
errors.Is(err, ErrProjectNotFound)
```

Use a custom error type when callers need its fields or distinct handling.

---

## 14. Use `errors.Is` / `errors.As` idiomatically

Do not manually inspect error strings.

Bad:

```go
if strings.Contains(err.Error(), "duplicate") {
```

Prefer the underlying driver's supported error type/code.

Example:

```go
var writeErr mongo.WriteException
if errors.As(err, &writeErr) {
    ...
}
```

Use the driver's error contract directly. A generic error-inspection layer is unnecessary for one known driver.

---

## 15. Use reflection only when types cannot express the operation

Search for:

```go
reflect.
```

Reflection is suspicious in ordinary business logic.

Bad:

```go
func isEmpty(value any) bool {
    v := reflect.ValueOf(value)
    ...
}
```

Prefer explicit field checks when they express the same operation.

Reflection is reasonable in areas such as:

- serializers
- frameworks
- generic libraries
- tooling

It should rarely appear in normal handlers/services/domain logic.

---

## 16. Do not use generics where concrete code is clearer

Check whether generic helpers remove repeated logic or just wrap a short expression:

```go
func Ptr[T any](value T) *T
func ValueOrDefault[T comparable](...)
func ConvertSlice[T any, R any](...)
func SafeCast[T any](...)
func GetOrDefault[K comparable, V any](...)
```

Use generics for repeated operations across types. Keep concrete code when the generic version adds parameters and indirection without removing duplication.

---

## 17. Remove generic map accessor utilities

Bad:

```go
func GetString(data map[string]any, key string) string
func GetInt(data map[string]any, key string) int
func GetBool(data map[string]any, key string) bool
```

This is usually evidence that structured data should have been decoded into a struct.

Prefer:

```go
type DeploymentEvent struct {
    ProjectID string `json:"project_id"`
    Port      int    `json:"port"`
    Enabled   bool   `json:"enabled"`
}
```

Then use:

```go
event.ProjectID
event.Port
event.Enabled
```

---

## 18. Decode JSON once at the boundary

Bad:

```go
var payload map[string]any

if err := json.Unmarshal(body, &payload); err != nil {
    return err
}

event, _ := payload["event"].(string)
data, _ := payload["data"].(map[string]any)
projectID, _ := data["project_id"].(string)
```

Prefer:

```go
type QueueEvent struct {
    Event string          `json:"event"`
    Data  json.RawMessage `json:"data"`
}
```

Then decode the event-specific payload once:

```go
type ProjectSyncEvent struct {
    ProjectID string `json:"project_id"`
}

var event ProjectSyncEvent

if err := json.Unmarshal(payload.Data, &event); err != nil {
    return fmt.Errorf("decode project sync event: %w", err)
}
```

After decoding, business logic should operate on typed structs.

---

## 19. Avoid `map[string]any` for database models

If MongoDB, JSONB, Redis, or another store returns known document shapes, define structs.

Bad:

```go
var document map[string]any
```

followed by:

```go
id, ok := document["domain"].(primitive.ObjectID)
```

Prefer:

```go
type DNSDocument struct {
    Domain primitive.ObjectID `bson:"domain"`
}
```

Then:

```go
document.Domain.Hex()
```

Fix broad types at the data-access boundary rather than adding extractors everywhere.

---

## 20. Remove fake defensive type assertions

Bad:

```go
value, ok := data.(map[string]any)
if !ok {
    return nil
}

domain, ok := value["domain"].(string)
if !ok {
    return nil
}
```

if the data came from a contract already controlled by the application.

Give controlled data a concrete type upstream. Validate external data when it enters the application.

---

## 21. Avoid excessive DTO/model duplication

Be suspicious when the same data has:

```go
ProjectRequest
ProjectDTO
ProjectInput
ProjectParams
ProjectData
ProjectModel
ProjectEntity
ProjectResponse
```

with nearly identical fields.

Separate types when their contracts differ. Layers that share a concept can share its type.

---

## 22. Remove redundant mappers

Look for functions like:

```go
func projectToDTO(project Project) ProjectDTO {
    return ProjectDTO{
        ID:   project.ID,
        Name: project.Name,
    }
}
```

when `ProjectDTO` and `Project` are effectively identical and no boundary requires the distinction.

Remove mappings such as:

```txt
toDTO
fromDTO
toModel
fromModel
toEntity
fromEntity
```

when the source and destination have the same representation.

---

## 23. Avoid constructors that do nothing useful

Bad:

```go
func NewProjectService(repo Repository) *ProjectService {
    return &ProjectService{
        repo: repo,
    }
}
```

This constructor can be reasonable if it provides a stable construction API.

But do not add constructors for simple data structs:

```go
func NewDomain(name string) Domain {
    return Domain{Name: name}
}
```

when:

```go
Domain{Name: name}
```

is clearer.

Keep constructors that establish invariants, perform setup, or provide a stable construction API.

---

## 24. Use literals for simple structs

Do not introduce Java-style builders for simple structs.

Bad:

```go
deployment := NewDeploymentBuilder().
    WithProjectID(projectID).
    WithRegion(region).
    WithPort(port).
    WithImage(image).
    Build()
```

Prefer:

```go
deployment := Deployment{
    ProjectID: projectID,
    Region:    region,
    Port:      port,
    Image:     image,
}
```

Keep a builder only when it simplifies construction compared with a struct literal or constructor.

---

## 25. Do not overuse functional options

Avoid:

```go
NewService(
    WithRepository(repo),
    WithLogger(logger),
    WithMetrics(metrics),
)
```

when all fields are required.

Prefer:

```go
NewService(repo, logger, metrics)
```

Reserve functional options for optional configuration. Pass required dependencies as arguments.

---

## 26. Avoid unnecessary factories

Bad:

```go
type RepositoryFactory struct{}

func (f *RepositoryFactory) CreateRepository(kind string) Repository
```

when the application has one concrete repository.

Prefer constructing the concrete dependency directly.

Use a factory when the application must select an implementation at runtime.

---

## 27. Avoid unnecessary dependency injection infrastructure

Pass dependencies explicitly:

```go
service := NewService(repo, logger)
```

Do not introduce:

- containers
- service locators
- registries
- providers
- dependency graphs
- reflection-based injection

unless they solve a dependency-wiring problem that direct calls cannot.

---

## 28. Prefer straightforward control flow

Bad:

```go
var shouldProcess bool

if project != nil {
    if project.Enabled {
        if project.Status == StatusActive {
            shouldProcess = true
        }
    }
}
```

Prefer early returns:

```go
if project == nil {
    return nil
}

if !project.Enabled {
    return nil
}

if project.Status != StatusActive {
    return nil
}

// actual work
```

Or when simple:

```go
shouldProcess := project != nil &&
    project.Enabled &&
    project.Status == StatusActive
```

Use early returns for a sequence of checks, or a boolean expression when the caller needs a boolean.

---

## 29. Prefer early returns over deep nesting

Bad:

```go
if err == nil {
    if project != nil {
        if project.Enabled {
            // 80 lines
        }
    }
}
```

Prefer:

```go
if err != nil {
    return err
}

if project == nil {
    return ErrProjectNotFound
}

if !project.Enabled {
    return nil
}

// main logic
```

Keep the happy path visually obvious.

---

## 30. Remove useless temporary variables

Bad:

```go
rawDomain := event.Domain
normalizedDomain := strings.TrimSpace(rawDomain)
domain := strings.ToLower(normalizedDomain)
```

Prefer:

```go
domain := strings.ToLower(strings.TrimSpace(event.Domain))
```

Keep intermediate variables when their names explain a step. Remove those that only rename a value.

---

## 31. Remove pointless boolean comparisons

Clean up:

```go
if enabled == true
if enabled == false
```

Prefer:

```go
if enabled
if !enabled
```

Unless an API uses nullable booleans where the distinction matters.

---

## 32. Remove redundant slice/map initialization

Question code like:

```go
items := make([]Item, 0)
```

when:

```go
var items []Item
```

is sufficient.

Likewise do not create:

```go
make(map[string]string)
```

until the map needs writes.

But keep capacity preallocation where profiling/data size makes it useful.

---

## 33. Do not copy slices/maps unnecessarily

Be suspicious of defensive copying with no mutation threat.

Bad:

```go
result := make([]string, len(input))
copy(result, input)
return result
```

unless ownership/mutation semantics require the copy.

Do not add allocations "for safety" without a concrete reason.

---

## 34. Avoid premature performance tricks

Do not introduce:

- `sync.Pool`
- manual buffer reuse
- unsafe conversions
- custom allocators
- elaborate caches
- goroutine pools
- lock-free structures

unless measurements show a problem they address.

---

## 35. Do not add goroutines unnecessarily

Be suspicious of:

```go
go func() {
    ...
}()
```

when the caller could wait for the result.

For each goroutine, account for its lifetime, cancellation, shared state, errors, and shutdown. Keep it when concurrent execution is needed or improves measured performance.

---

## 36. Avoid channel-based architecture for simple synchronous work

Bad:

```txt
handler
↓
channel
↓
worker
↓
channel
↓
processor
```

for logic that could simply be:

```go
processor.Process(ctx, event)
```

Use channels to synchronize concurrent work. Use direct calls for synchronous work.

---

## 37. Use `context.Context` correctly

Do not:

- store context permanently on structs
- create `context.Background()` deep in request processing
- accept `context.Context` where cancellation/deadlines are irrelevant
- nil-check context

Bad:

```go
if ctx == nil {
    ctx = context.Background()
}
```

A context parameter should not be nil.

Pass the caller's context through I/O boundaries.

Typical signature:

```go
func (s *Service) GetProject(ctx context.Context, id string) (*Project, error)
```

Do not create new contexts just to satisfy a function signature.

---

## 38. Avoid wrapping every operation in timeouts

Do not mechanically write:

```go
ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
defer cancel()
```

inside every repository/service function.

Set timeouts at boundaries where the policy is known. Add an inner timeout only when that operation needs a shorter limit than its caller.

---

## 39. Keep logging simple

Remove logs that repeat the execution sequence:

```go
logger.Info("entering CreateProject")
logger.Info("validating project")
logger.Info("calling repository")
logger.Info("repository completed")
logger.Info("leaving CreateProject")
```

Log failures, state transitions, and external operations that help diagnose a problem.

---

## 40. Avoid logging and returning the same error at every layer

Bad:

```go
result, err := repo.Get(ctx, id)
if err != nil {
    logger.Error("failed to get project", "error", err)
    return nil, err
}
```

if the caller will also log it.

Return errors from libraries and services. Log at the handler, worker, or supervisor responsible for handling the failure.

---

## 41. Remove obvious comments

Delete comments like:

```go
// Check if project exists.
if project == nil {
```

```go
// Return the result.
return result
```

```go
// Convert string to lowercase.
domain = strings.ToLower(domain)
```

Keep comments for:

- business rules
- invariants
- non-obvious decisions
- external system quirks
- workarounds
- concurrency reasoning

Comments should explain why, not narrate syntax.

---

## 42. Avoid over-packaging

Do not create a package for every type/helper.

Bad:

```txt
internal/
  domainparser/
  stringutils/
  validationhelper/
  projectmapper/
  pointerhelper/
  responsebuilder/
```

Group code by domain or capability. A new helper does not need its own package.

---

## 43. Remove vague utility packages

Audit packages named:

```txt
utils
helpers
common
shared
misc
core
base
```

Move useful functions to the package that owns their behavior. Inline trivial helpers instead of moving them to another utility package.

---

## 44. Avoid unnecessary wrapper structs

Bad:

```go
type ProjectID struct {
    Value string
}
```

when a plain string is sufficient.

A custom type may be appropriate:

```go
type ProjectID string
```

if it prevents mixing IDs or adds domain behavior.

But do not wrap primitives in structs without a concrete benefit.

---

## 45. Use custom primitive types selectively

This can be useful:

```go
type ProjectID string
type Region string
```

when it prevents accidental mixing.

But do not produce:

```go
type ProjectName string
type ProjectDescription string
type ProjectImage string
type ProjectStatusString string
```

for every field.

Use a domain type when it prevents invalid assignments or adds domain behavior.

---

## 46. Do not duplicate standard library functionality

Before keeping a helper, check whether Go already has the operation.

Prefer:

```go
strings.TrimSpace
strings.ToLower
slices.Contains
maps.Clone
errors.Is
errors.As
cmp.Or
strconv.Atoi
```

where appropriate.

Do not maintain custom helpers that poorly reimplement the standard library.

---

## 47. Avoid regex when normal string operations work

Bad:

```go
regexp.MustCompile(`\s+`).ReplaceAllString(...)
```

for simple trimming or known delimiters.

Use `strings` functions for trimming and known delimiters. Keep regex for patterns those functions do not express.

---

## 48. Simplify string formatting

Avoid:

```go
fmt.Sprintf("%s", value)
```

when `value` is already a string.

Avoid:

```go
fmt.Sprintf("%d", n)
```

in hot/simple paths when:

```go
strconv.Itoa(n)
```

is clearer.

Keep readable formatting unless measurements justify changing it.

---

## 49. Do not create validators for trusted internal structs

Bad:

```go
func validateProject(project Project) error {
    if project.ID == "" {
        return errors.New("missing project ID")
    }
    ...
}
```

called in every internal service.

If `Project` is created from external input, validate when creating/parsing it.

Do not repeatedly validate the same object throughout the system.

---

## 50. Keep boundary validation

Do not blindly remove validation.

Validation is appropriate for:

- HTTP requests
- query/path parameters
- queue messages
- webhooks
- config/env vars
- external APIs
- user input
- decoded untrusted JSON
- persisted schemaless documents

Validate these inputs before passing them to internal code. Removing repeated internal checks must not remove the boundary check.

---

## 51. Avoid excessive validation libraries

If normal Go code is sufficient:

```go
if req.Domain == "" {
    return ErrDomainRequired
}
```

Do not introduce a large validation framework solely to avoid three `if` statements.

Keep an existing validation library when it simplifies the schema checks.

---

## 52. Keep business rules explicit

Name the business condition in the check.

Bad:

```go
if validator.IsValid(project) {
```

when the real business rule is:

```go
if project.Status != StatusActive {
    return ErrProjectInactive
}
```

Domain rules should be visible in the code.

---

## 53. Avoid giant config objects passed everywhere

Bad:

```go
func Process(ctx context.Context, cfg Config, options Options, metadata Metadata)
```

when the function needs:

```go
projectID
region
```

Pass only the data the function uses.

---

## 54. Do not introduce unnecessary option structs

Bad:

```go
type GetProjectOptions struct {
    ID string
}
```

for:

```go
GetProject(ctx, GetProjectOptions{ID: id})
```

Prefer:

```go
GetProject(ctx, id)
```

Keep option structs for related parameters that travel together or for optional settings.

---

## 55. Avoid unnecessary return structs

Bad:

```go
type ExistsResult struct {
    Exists bool
}
```

Prefer:

```go
func Exists(...) (bool, error)
```

Use a struct when related return values belong together.

---

## 56. Avoid needless named return values

Bad:

```go
func GetProject(id string) (project *Project, err error) {
    ...
}
```

unless callers need names to distinguish the results or a deferred function updates them.

Prefer:

```go
func GetProject(id string) (*Project, error) {
```

Avoid naked returns in non-trivial functions.

---

## 57. Remove defensive `recover()` usage

Search for:

```go
defer func() {
    if r := recover(); r != nil {
        ...
    }
}()
```

Reserve `recover` for process or request boundaries that must keep running after a panic. Return errors for expected failures in business functions.

---

## 58. Avoid `panic` for normal errors

Do not use `panic` for:

- validation failures
- missing DB rows
- network errors
- malformed user input

Return errors.

Panics are appropriate for states that make program initialization or continued execution impossible.

---

## 59. Pass mutable dependencies explicitly

Review:

```go
var defaultClient ...
var globalConfig ...
var singleton ...
```

Globals are fine for true constants/immutable package state.

Do not use mutable package globals as a shortcut for dependency wiring.

Pass dependencies explicitly.

---

## 60. Do not abstract simple database operations unnecessarily

Bad:

```txt
Service
→ Repository
→ Store
→ DAO
→ QueryExecutor
→ sql.DB
```

A repository can own SQL or Mongo queries. Remove wrappers that only forward its methods.

---

## 61. Keep SQL/query code obvious

Use plain queries for static SQL. Use a query builder when queries need dynamic composition.

Plain SQL is often easier to understand:

```go
const query = `
    SELECT id, name
    FROM projects
    WHERE id = $1
`
```

Do not hide straightforward SQL behind abstraction solely to avoid writing SQL.

---

## 62. Keep transaction handling direct

Do not invent elaborate:

```go
TransactionManager
UnitOfWork
TransactionProvider
TransactionRunner
```

if this suffices:

```go
tx, err := db.BeginTx(ctx, nil)
if err != nil {
    return err
}

defer tx.Rollback()

...

return tx.Commit()
```

Abstract transaction handling only when repeated complexity justifies it.

---

## 63. Use constants where they clarify meaning

Do not replace every string with a constant.

Good:

```go
const duplicateKeyCode = 11000
```

when the number has domain/driver meaning.

Unnecessary:

```go
const emptyString = ""
const trueValue = true
```

Constants should communicate meaning.

---

## 64. Do not over-enum strings

Custom string constants are useful:

```go
type DeploymentStatus string

const (
    DeploymentPending DeploymentStatus = "pending"
    DeploymentRunning DeploymentStatus = "running"
)
```

But do not create enums for every arbitrary string if there is no closed set of valid values.

---

## 65. Prefer readable switches

Go `switch` is often better than abstraction.

Bad:

```go
handlers := map[string]func(Event) error{
    "insert": handleInsert,
    "delete": handleDelete,
}
```

when a simple switch is clearer:

```go
switch event.Type {
case "insert":
    return handleInsert(event)

case "delete":
    return handleDelete(event)

default:
    return ErrUnsupportedEvent
}
```

Use a dispatch map when handlers need dynamic registration.

---

## 66. Do not force polymorphism

If there are only two slightly different cases, a switch may be clearer than:

```go
type Strategy interface {
    Execute(...)
}
```

plus:

```go
InsertStrategy
DeleteStrategy
ReplaceStrategy
```

Go does not require every branch to become polymorphism.

---

## 67. Avoid excessive mocks

Test real implementations where practical. Use small interfaces to substitute expensive or external dependencies, rather than mocking every internal type.

---

## 68. Keep tests simple too

Apply the cleanup to tests.

Remove:

- builders and fixture systems that make inputs hard to see
- helper chains that hide assertions
- mocks for pure logic
- untyped data whose shape is known

Prefer explicit table-driven tests where appropriate:

```go
tests := []struct {
    name string
    in   string
    want string
}{
    {"lowercase", "EXAMPLE.COM", "example.com"},
    {"trim", " example.com ", "example.com"},
}
```

Do not make tests harder to understand than the code they test.

---

## 69. Do not blindly remove idiomatic Go error handling

Keep error handling that propagates a failure:

```go
if err != nil {
    return err
}
```

Likewise:

```go
value, ok := m[key]
```

```go
if !ok {
    ...
}
```

and:

```go
if project == nil {
    ...
}
```

are correct when the error or missing value can occur. Check the contract before deleting them.

---

## 70. Optimize for code reduction, not line golf

Reduce code by removing unnecessary concepts. Do not compress the same logic into harder-to-read expressions.

Bad cleanup:

```go
if err := func() error { ... }(); err != nil { return fmt.Errorf(...) }
```

Prefer boring readable Go.

---

## 71. Fix the root type instead of adding helpers

Whenever you see:

```go
asString(value)
asObjectID(value)
extractDomain(value)
safeValue(value)
toMap(value)
```

trace where `value` originated.

Ask:

1. Why isn't this value already strongly typed?
2. Is this data external?
3. Can it be decoded into a concrete struct at the boundary?
4. Can downstream functions accept the concrete type?
5. Can this helper then disappear?

Always prefer fixing the source of poor typing.

---

## 72. Check features with many architectural layers

Inspect small features split across files such as:

```txt
interfaces.go
factory.go
builder.go
mapper.go
converter.go
validator.go
utils.go
helpers.go
manager.go
processor.go
service.go
repository.go
```

Trace what each file owns. Collapse layers that only forward calls or map identical structures.

---

## 73. Search patterns to audit

Search the repository for:

```txt
any
interface{}
map[string]any
map[string]interface{}
reflect.
recover(
panic(
fmt.Sprintf
strconv.
errors.New
fmt.Errorf
errors.As
errors.Is
== nil
!= nil
type .* interface
Factory
Builder
Manager
Processor
Helper
Utils
Mapper
Converter
Validator
Options
Params
DTO
Entity
Model
ValueOr
Safe
Normalize
Extract
Resolve
Parse
GetString
AsString
ToString
With
context.Background
context.TODO
sync.Pool
go func
make([]
```

Treat matches as inspection points, not violations. Trace their callers before deciding to change them.

---

## 74. Check that each change removes complexity

- Delete checks for states that the contract rules out.
- Fix upstream types instead of adding downstream conversions.
- Replace interfaces that have no substitution or consumer-driven purpose with concrete types.
- Inline helpers that neither name an operation nor remove repeated logic.
- Remove abstractions that add more indirection than the complexity they hide.
- Use direct Go code when it makes the behavior easier to trace.

---

## 75. Desired style

Prefer code like:

```go
func (s *Service) MapDomain(ctx context.Context, event DomainMapEvent) error {
    domain := strings.ToLower(strings.TrimSpace(event.Domain))

    return s.domains.Map(ctx, event.ProjectID, domain)
}
```

over:

```go
func (s *Service) MapDomain(ctx context.Context, raw any) error {
    event, err := convertToDomainMapEvent(raw)
    if err != nil {
        return fmt.Errorf("failed converting domain event: %w", err)
    }

    projectID := safeString(event.ProjectID)
    if projectID == "" {
        return nil
    }

    domain := normalizeStringValue(event.Domain)
    if domain == "" {
        return nil
    }

    return s.domainManager.ProcessDomainMapping(
        ctx,
        NewDomainMappingParams(projectID, domain),
    )
}
```

---

## 76. Refactoring process

Work feature-by-feature.

For each feature:

### Step 1

Identify where data enters the system.

Examples:

- HTTP
- queue
- Kafka/NATS/RabbitMQ
- MongoDB
- PostgreSQL
- Redis
- webhook
- external API
- environment/config

### Step 2

Give the input a concrete type.

### Step 3

Validate/decode once.

### Step 4

Follow the data through the application.

Remove unnecessary:

- `any`
- type assertions
- generic maps
- nil guards
- converters
- extractors
- wrapper structs
- interfaces
- pass-through methods
- duplicate DTOs
- generic helpers

### Step 5

Collapse forwarding layers.

### Step 6

Delete dead abstractions.

### Step 7

Follow [workflow.md](workflow.md) for test execution and static analysis.

Use the project's normal commands, including where applicable:

```bash
go test ./...
go vet ./...
staticcheck ./...
```

Run formatters after changes:

```bash
gofmt
```

Preserve behavior during style changes.

---

## 77. Preserve required safeguards

Do not remove:

- useful interfaces
- error wrapping that identifies the operation or resource
- legitimate nil handling
- boundary validation
- context propagation
- proper resource cleanup
- `defer rows.Close()`
- `defer resp.Body.Close()`
- transaction rollback safety
- mutexes protecting real shared state
- channels that synchronize concurrent work
- driver-specific error handling
- correct integer/error checks
- security-related checks

A smaller diff is not a reason to weaken these safeguards.

---

## 78. Judge the result by the call path

A reader should be able to follow typed input through validation to the operation that uses it. Remove conversions, duplicate models, and forwarding layers that interrupt that path. Keep business rules and failure handling visible.

Count the definitions a reader must visit to understand an operation. Changing more files is not evidence of a better cleanup.

---

## 79. Fix the data model rather than adding guards

A guarded type assertion still leaves the data untyped.

Do not turn:

```go
value := data["domain"].(string)
```

into:

```go
value, ok := data["domain"]
if !ok {
    return ""
}

domain, ok := value.(string)
if !ok {
    return ""
}
```

and call that a cleanup.

The correct solution is usually:

```go
type Event struct {
    Domain string `json:"domain"`
}
```

followed by:

```go
event.Domain
```

Likewise, do not replace a simple direct call with:

```txt
interface
→ implementation
→ manager
→ helper
→ converter
→ validator
→ actual function
```

Decode the input into the right type, validate it, and pass that type through the application.
