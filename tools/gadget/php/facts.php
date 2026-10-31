<?php
/**
 * Emit per-file PHP facts for the cross-class gadget graph.
 *
 *   find <root> -name '*.php' -print | php facts.php --root <root>
 *
 * One JSON object per line. Requires nikic/php-parser (vendor/ is ignored).
 */
declare(strict_types=1);

require __DIR__ . '/vendor/autoload.php';

use PhpParser\Node;
use PhpParser\NodeFinder;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;
use PhpParser\NodeVisitorAbstract;
use PhpParser\ParserFactory;

final class FactVisitor extends NodeVisitorAbstract
{
    public array $classes = [];
    public array $errors = [];
    private array $classStack = [];
    private array $methodStack = [];
    private array $locals = [];
    private array $uses = [];
    private string $namespace = '';
    private NodeFinder $finder;
    private string $file;

    public function __construct(string $file)
    {
        $this->file = $file;
        $this->finder = new NodeFinder();
    }

    private function typeNames(?Node $type): array
    {
        if ($type === null) {
            return [];
        }
        if ($type instanceof Node\NullableType) {
            return $this->typeNames($type->type);
        }
        if ($type instanceof Node\UnionType || $type instanceof Node\IntersectionType) {
            $out = [];
            foreach ($type->types as $part) {
                $out = array_merge($out, $this->typeNames($part));
            }
            return array_values(array_unique($out));
        }
        if ($type instanceof Node\Name) {
            return [$this->resolveName($type)];
        }
        if ($type instanceof Node\Identifier) {
            $builtin = ['int', 'float', 'string', 'bool', 'array', 'callable',
                'iterable', 'object', 'mixed', 'void', 'null', 'false', 'true'];
            return in_array(strtolower($type->toString()), $builtin, true)
                ? [] : [$type->toString()];
        }
        return [];
    }

    private function resolveName(Node\Name $name): string
    {
        $resolved = $name->getAttribute('resolvedName');
        if ($resolved instanceof Node\Name) {
            return $resolved->toString();
        }
        if ($name->isFullyQualified()) {
            return ltrim($name->toString(), '\\');
        }
        $raw = $name->toString();
        $parts = explode('\\', $raw);
        $first = strtolower($parts[0]);
        if (isset($this->uses[$first])) {
            $parts[0] = $this->uses[$first];
            return implode('\\', $parts);
        }
        return $this->namespace !== '' ? $this->namespace . '\\' . $raw : $raw;
    }

    private function addProp(array &$info, string $name, array $types, int $line, bool $static): void
    {
        $types = array_values(array_unique(array_filter($types)));
        if (!isset($info['properties'][$name])) {
            $info['properties'][$name] = ['types' => [], 'line' => $line, 'static' => $static];
        }
        $info['properties'][$name]['types'] = array_values(array_unique(
            array_merge($info['properties'][$name]['types'], $types)
        ));
    }

    private function describe(Node\Stmt\ClassLike $node): array
    {
        $name = isset($node->namespacedName)
            ? $node->namespacedName->toString()
            : ($node->name?->toString() ?? "anonymous@{$this->file}:{$node->getStartLine()}");
        $extends = [];
        if ($node instanceof Node\Stmt\Class_ && $node->extends !== null) {
            $extends[] = $node->extends->toString();
        }
        if ($node instanceof Node\Stmt\Interface_) {
            foreach ($node->extends as $parent) {
                $extends[] = $parent->toString();
            }
        }
        $implements = [];
        if (property_exists($node, 'implements')) {
            foreach ($node->implements as $iface) {
                $implements[] = $iface->toString();
            }
        }
        $traits = [];
        foreach ($node->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\TraitUse) {
                foreach ($stmt->traits as $trait) {
                    $traits[] = $trait->toString();
                }
            }
        }
        $info = [
            'name' => $name,
            'file' => $this->file,
            'line' => $node->getStartLine(),
            'extends' => array_values(array_unique($extends)),
            'implements' => array_values(array_unique($implements)),
            'traits' => array_values(array_unique($traits)),
            'interface' => $node instanceof Node\Stmt\Interface_,
            'trait' => $node instanceof Node\Stmt\Trait_,
            'abstract' => method_exists($node, 'isAbstract') ? $node->isAbstract() : false,
            'properties' => [],
            'methods' => [],
        ];
        foreach ($node->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\Property) {
                foreach ($stmt->props as $prop) {
                    $types = $this->typeNames($stmt->type);
                    if ($prop->default instanceof Node\Expr\New_
                        && $prop->default->class instanceof Node\Name) {
                        $types[] = $prop->default->class->toString();
                    }
                    $this->addProp($info, $prop->name->toString(), $types,
                        $stmt->getStartLine(), $stmt->isStatic());
                }
                continue;
            }
            if (!$stmt instanceof Node\Stmt\ClassMethod) {
                continue;
            }
            $params = [];
            foreach ($stmt->params as $param) {
                $paramName = $param->var->name ?? null;
                if (!is_string($paramName)) {
                    continue;
                }
                $types = $this->typeNames($param->type);
                $params[] = ['name' => $paramName, 'types' => $types];
                if (($param->flags ?? 0) !== 0) {
                    $this->addProp($info, $paramName, $types,
                        $param->getStartLine(), false);
                }
            }
            $method = $stmt->name->toString();
            $info['methods'][$method] = [
                'name' => $method,
                'line' => $stmt->getStartLine(),
                'end' => $stmt->getEndLine(),
                'static' => $stmt->isStatic(),
                'abstract' => $stmt->isAbstract(),
                'returns' => $this->typeNames($stmt->returnType),
                'params' => $params,
                'calls' => [],
                'strings' => [],
            ];
        }
        return $info;
    }

    private function resolveType(string $name, string $class): array
    {
        $name = ltrim($name, '\\');
        if ($name === 'self' || $name === 'static') {
            return [$class];
        }
        if ($name === 'parent') {
            return $this->classes[$class]['extends'] ?? [];
        }
        return [$name];
    }

    private function propTypes(string $class, string $prop): array
    {
        $types = $this->classes[$class]['properties'][$prop]['types'] ?? [];
        $out = [];
        foreach ($types as $type) {
            $out = array_merge($out, $this->resolveType($type, $class));
        }
        return array_values(array_unique(array_filter($out)));
    }

    private function infer(Node $expr): array
    {
        $class = end($this->classStack) ?: '';
        if ($expr instanceof Node\Expr\PropertyFetch
            && $expr->var instanceof Node\Expr\Variable
            && $expr->var->name === 'this'
            && $expr->name instanceof Node\Identifier) {
            return $this->propTypes($class, $expr->name->toString());
        }
        if ($expr instanceof Node\Expr\Variable && is_string($expr->name)) {
            return $this->locals[$expr->name] ?? [];
        }
        if ($expr instanceof Node\Expr\New_ && $expr->class instanceof Node\Name) {
            return [$expr->class->toString()];
        }
        if ($expr instanceof Node\Expr\Clone_) {
            return $this->infer($expr->expr);
        }
        if ($expr instanceof Node\Expr\Assign) {
            return $this->infer($expr->expr);
        }
        if ($expr instanceof Node\Expr\Ternary) {
            return array_values(array_unique(array_merge(
                $this->infer($expr->if ?? $expr->cond),
                $this->infer($expr->else)
            )));
        }
        if ($expr instanceof Node\Expr\BinaryOp\Coalesce) {
            return array_values(array_unique(array_merge(
                $this->infer($expr->left), $this->infer($expr->right)
            )));
        }
        if (($expr instanceof Node\Expr\MethodCall
                || $expr instanceof Node\Expr\NullsafeMethodCall)
            && $expr->var instanceof Node\Expr\Variable
            && $expr->var->name === 'this'
            && $expr->name instanceof Node\Identifier
            && isset($this->classes[$class]['methods'][$expr->name->toString()])) {
            return $this->classes[$class]['methods'][$expr->name->toString()]['returns'];
        }
        return [];
    }

    private function record(array $call): void
    {
        $class = end($this->classStack);
        $method = end($this->methodStack);
        if (!$class || !$method
            || !isset($this->classes[$class]['methods'][$method])) {
            return;
        }
        $this->classes[$class]['methods'][$method]['calls'][] = $call;
    }

    private function stringUse(Node $expr): void
    {
        $types = $this->infer($expr);
        if ($types) {
            $this->record([
                'kind' => 'string', 'line' => $expr->getStartLine(),
                'targets' => $types, 'method' => '__toString',
            ]);
        }
    }

    public function enterNode(Node $node)
    {
        if ($node instanceof Node\Stmt\Namespace_) {
            $this->namespace = $node->name?->toString() ?? '';
            return null;
        }
        if ($node instanceof Node\Stmt\Use_) {
            foreach ($node->uses as $use) {
                if ($use->type === Node\Stmt\Use_::TYPE_NORMAL || $use->type === 0) {
                    $alias = $use->alias?->toString() ?? $use->name->getLast();
                    $this->uses[strtolower($alias)] = $use->name->toString();
                }
            }
            return null;
        }
        if ($node instanceof Node\Stmt\GroupUse) {
            foreach ($node->uses as $use) {
                if ($use->type === Node\Stmt\Use_::TYPE_NORMAL || $use->type === 0) {
                    $full = $node->prefix->toString() . '\\' . $use->name->toString();
                    $alias = $use->alias?->toString() ?? $use->name->getLast();
                    $this->uses[strtolower($alias)] = $full;
                }
            }
            return null;
        }
        if ($node instanceof Node\Stmt\ClassLike) {
            $info = $this->describe($node);
            $this->classes[$info['name']] = $info;
            $this->classStack[] = $info['name'];
            return null;
        }
        if ($node instanceof Node\Stmt\ClassMethod) {
            $class = end($this->classStack);
            if (!$class || !isset($this->classes[$class])) {
                return null;
            }
            $method = $node->name->toString();
            $this->methodStack[] = $method;
            $this->locals = [];
            foreach ($this->classes[$class]['methods'][$method]['params'] as $param) {
                $this->locals[$param['name']] = $param['types'];
            }
            foreach ($this->finder->findInstanceOf($node->stmts ?? [],
                Node\Expr\Assign::class) as $assign) {
                $types = $this->infer($assign->expr);
                if (!$types) {
                    continue;
                }
                $var = $assign->var;
                if ($var instanceof Node\Expr\PropertyFetch
                    && $var->var instanceof Node\Expr\Variable
                    && $var->var->name === 'this'
                    && $var->name instanceof Node\Identifier) {
                    $this->addProp($this->classes[$class],
                        $var->name->toString(), $types,
                        $assign->getStartLine(), false);
                } elseif ($var instanceof Node\Expr\Variable
                    && is_string($var->name)) {
                    $this->locals[$var->name] = array_values(array_unique(
                        array_merge($this->locals[$var->name] ?? [], $types)
                    ));
                }
            }
            return null;
        }
        $class = end($this->classStack);
        $method = end($this->methodStack);
        if (!$class || !$method
            || !isset($this->classes[$class]['methods'][$method])) {
            return null;
        }
        if ($node instanceof Node\Expr\MethodCall
            || $node instanceof Node\Expr\NullsafeMethodCall) {
            $name = $node->name instanceof Node\Identifier
                ? $node->name->toString() : null;
            $receiver = $node->var;
            $kind = 'expr';
            $prop = null;
            $varName = null;
            $targets = [];
            if ($receiver instanceof Node\Expr\Variable
                && $receiver->name === 'this') {
                $kind = 'this';
                $targets = [$class];
            } elseif ($receiver instanceof Node\Expr\PropertyFetch
                && $receiver->var instanceof Node\Expr\Variable
                && $receiver->var->name === 'this'
                && $receiver->name instanceof Node\Identifier) {
                $kind = 'property';
                $prop = $receiver->name->toString();
                $targets = $this->infer($receiver);
            } elseif ($receiver instanceof Node\Expr\Variable
                && is_string($receiver->name)) {
                $kind = 'variable';
                $varName = $receiver->name;
                $targets = $this->infer($receiver);
            } elseif ($receiver instanceof Node\Expr\New_) {
                $kind = 'new';
                $targets = $this->infer($receiver);
            }
            $this->record([
                'kind' => 'method', 'name' => $name, 'line' => $node->getStartLine(),
                'targets' => $targets, 'receiver_kind' => $kind,
                'prop' => $prop, 'var' => $varName, 'dynamic' => $name === null,
            ]);
        } elseif ($node instanceof Node\Expr\StaticCall) {
            $targets = [];
            if ($node->class instanceof Node\Name) {
                $targets = $this->resolveType($node->class->toString(), $class);
            }
            $this->record([
                'kind' => 'static', 'line' => $node->getStartLine(),
                'targets' => $targets,
                'name' => $node->name instanceof Node\Identifier
                    ? $node->name->toString() : null,
                'dynamic' => !$node->name instanceof Node\Identifier,
            ]);
        } elseif ($node instanceof Node\Expr\FuncCall) {
            $this->record([
                'kind' => 'function', 'line' => $node->getStartLine(),
                'name' => $node->name instanceof Node\Name
                    ? $node->name->toString() : null,
                'dynamic' => !$node->name instanceof Node\Name,
            ]);
        } elseif ($node instanceof Node\Expr\New_) {
            $this->record([
                'kind' => 'new', 'line' => $node->getStartLine(),
                'targets' => $this->infer($node),
            ]);
        } elseif ($node instanceof Node\Expr\Include_) {
            $this->record([
                'kind' => 'include', 'line' => $node->getStartLine(),
                'targets' => $this->infer($node->expr),
            ]);
        } elseif ($node instanceof Node\Expr\Eval_) {
            $this->record(['kind' => 'eval', 'line' => $node->getStartLine()]);
        } elseif ($node instanceof Node\Expr\BinaryOp\Concat) {
            $this->stringUse($node->left);
            $this->stringUse($node->right);
        } elseif ($node instanceof Node\Stmt\Echo_) {
            foreach ($node->exprs as $expr) {
                $this->stringUse($expr);
            }
        } elseif ($node instanceof Node\Expr\Print_) {
            $this->stringUse($node->expr);
        } elseif ($node instanceof Node\Expr\Cast\String_) {
            $this->stringUse($node->expr);
        } elseif ($node instanceof Node\Scalar\InterpolatedString
            || $node instanceof Node\Scalar\Encapsed) {
            foreach ($node->parts as $part) {
                if ($part instanceof Node\Expr) {
                    $this->stringUse($part);
                }
            }
        }
        return null;
    }

    public function leaveNode(Node $node)
    {
        if ($node instanceof Node\Stmt\ClassMethod) {
            array_pop($this->methodStack);
            $this->locals = [];
        } elseif ($node instanceof Node\Stmt\ClassLike) {
            array_pop($this->classStack);
        }
        return null;
    }
}

$options = getopt('', ['root:']);
$root = rtrim($options['root'] ?? getcwd(), '/');
$parser = (new ParserFactory())->createForNewestSupportedVersion();
$stdin = fopen('php://stdin', 'r');
$count = 0;
while (($line = fgets($stdin)) !== false) {
    $path = trim($line);
    if ($path === '') {
        continue;
    }
    $relative = $path;
    if (str_starts_with($path, $root . '/')) {
        $relative = substr($path, strlen($root) + 1);
    }
    $code = @file_get_contents($path);
    if ($code === false) {
        fwrite(STDOUT, json_encode([
            'file' => $relative, 'classes' => [], 'error' => 'unreadable',
        ], JSON_UNESCAPED_SLASHES) . "\n");
        continue;
    }
    $visitor = new FactVisitor($relative);
    $traverser = new NodeTraverser();
    $traverser->addVisitor(new NameResolver(null, ['replaceNodes' => true]));
    $traverser->addVisitor($visitor);
    try {
        $ast = $parser->parse($code);
        $traverser->traverse($ast);
        $record = ['file' => $relative, 'classes' => array_values($visitor->classes)];
    } catch (Throwable $error) {
        $record = ['file' => $relative, 'classes' => [],
            'error' => $error->getMessage()];
    }
    fwrite(STDOUT, json_encode($record,
        JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) . "\n");
    $count++;
    if ($count % 200 === 0) {
        gc_collect_cycles();
    }
}
